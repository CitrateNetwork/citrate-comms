/**
 * MCP endpoint (JSON-RPC 2.0 over HTTP POST) — exposes the SAME comms tool registry
 * (lib/ai/tools.ts) the chat route uses, so other federation agents / the native
 * bridge can reach the comms tools without drift (explorer ADR-003). Workspace-scoped
 * + auth-gated: any active member may list/call read tools; the tools self-enforce
 * RBAC for the role=Agent caller and audit every call.
 *
 * S0 serves the read pair (crm.read, memory.recall). Write/terminal tools join as
 * they land, gated by HITL — the MCP surface inherits the same gates automatically.
 */
import { z } from "zod";
import { requireMember, GuardError, type MemberCtx } from "@/lib/tenant/guard";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { citrateCommsTools, IMPLEMENTED_TOOLS, ToolDenied } from "@/lib/ai/tools";
import { loadFieldDefsByEntity } from "@/lib/domain/crm-fields";

export const runtime = "nodejs";

const PROTOCOL_VERSION = "2024-11-05";
/** PBA-L3c-006: a JSON-RPC batch may carry at most this many messages. */
export const MAX_BATCH = 10;
const SERVER_INFO = { name: "citrate-comms-agents", version: "0.1.0" };

interface McpTool {
  description?: string;
  inputSchema: z.ZodType;
  execute: (args: unknown) => Promise<unknown>;
}
type Json = Record<string, unknown>;

export async function buildTools(workspaceId: string, ctx: Pick<MemberCtx, "sub" | "role">) {
  return citrateCommsTools({
    workspaceId,
    invokedBySub: ctx.sub,
    // CM2-B-B002: bind the tool surface to the CALLER's real role — never a hardcoded
    // "Agent". A human drives this endpoint directly; a Guest (read-only) must not
    // receive Agent-level post/write capability. Each tool then self-enforces RBAC.
    agentRole: ctx.role,
    allow: new Set(IMPLEMENTED_TOOLS),
    fieldDefsByEntity: await loadFieldDefsByEntity(workspaceId),
  }) as unknown as Record<string, McpTool>;
}

function jsonSchema(t: McpTool): Json {
  const js = z.toJSONSchema(t.inputSchema, { target: "draft-7" }) as Json;
  delete js.$schema;
  return js;
}

function toolList(tools: Record<string, McpTool>) {
  return Object.entries(tools).map(([name, t]) => ({
    name,
    description: t.description ?? "",
    inputSchema: jsonSchema(t),
  }));
}

interface RpcReq {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Json;
}

function rpcOk(id: RpcReq["id"], result: unknown) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}
function rpcErr(id: RpcReq["id"], code: number, message: string, data?: unknown) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } };
}

type Charge = () => Promise<boolean>;

async function handleOne(msg: RpcReq, tools: Record<string, McpTool>, charge: Charge): Promise<object | null> {
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return rpcErr(msg.id ?? null, -32600, "Invalid Request");
  }
  const id = msg.id ?? null;
  const isNotification = msg.id === undefined;
  switch (msg.method) {
    case "initialize":
      return rpcOk(id, { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO });
    case "ping":
      return rpcOk(id, {});
    case "notifications/initialized":
      return isNotification ? null : rpcOk(id, {});
    case "tools/list":
      return rpcOk(id, { tools: toolList(tools) });
    case "tools/call": {
      const params = msg.params ?? {};
      const name = params.name as string | undefined;
      const rawArgs = (params.arguments as Json) ?? {};
      const t = name ? tools[name] : undefined;
      if (!t) return rpcErr(id, -32602, `Unknown tool: ${name ?? "(missing)"}`);
      const parsed = t.inputSchema.safeParse(rawArgs);
      if (!parsed.success) {
        return rpcErr(id, -32602, "Invalid params", parsed.error.issues.map((e) => ({ path: e.path.join("."), message: e.message })));
      }
      // PBA-L3c-006: every tool call is charged against the caller's rate limit — a
      // batch is not a way to buy N calls for one token.
      if (!(await charge())) return rpcErr(id, -32000, "Rate limit exceeded");
      try {
        const result = await t.execute(parsed.data);
        return rpcOk(id, { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result as Json, isError: false });
      } catch (err) {
        // PBA-L3c-024: only deliberate refusals carry their message; anything else (DB,
        // driver, upstream) is logged server-side and returned generically.
        const message = err instanceof ToolDenied ? err.message : "tool execution failed";
        if (!(err instanceof ToolDenied)) console.error("[mcp] tool error", name, err);
        return rpcOk(id, { content: [{ type: "text", text: `Error: ${message}` }], isError: true });
      }
    }
    default:
      return rpcErr(id, -32601, `Method not found: ${msg.method}`);
  }
}

/** Discovery manifest. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const tools = await buildTools(id, ctx);
    return Response.json({
      name: SERVER_INFO.name,
      version: SERVER_INFO.version,
      protocol: "mcp",
      protocolVersion: PROTOCOL_VERSION,
      transport: "json-rpc-2.0 over HTTP POST",
      capabilities: { tools: { listChanged: false } },
      tools: toolList(tools),
    });
  } catch (e) {
    if (e instanceof GuardError) return Response.json({ error: e.message }, { status: e.status });
    return Response.json({ error: "internal_error" }, { status: 500 });
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  let workspaceId: string;
  let ctx: MemberCtx;
  try {
    const { id } = await params;
    workspaceId = id;
    ctx = await requireMember(req, workspaceId);
  } catch (e) {
    if (e instanceof GuardError) return Response.json(rpcErr(null, -32000, e.message), { status: e.status });
    return Response.json(rpcErr(null, -32603, "internal error"), { status: 500 });
  }

  const rl = await limit(`mcp:${hashId(ctx.sub)}`);
  if (!rl.success) {
    return Response.json(rpcErr(null, -32000, "Rate limit exceeded"), { status: 429 });
  }

  const tools = await buildTools(workspaceId, ctx);

  let bodyJson: unknown;
  try {
    bodyJson = await req.json();
  } catch {
    return Response.json(rpcErr(null, -32700, "Parse error"), { status: 400 });
  }

  const charge: Charge = async () => (await limit(`mcp-call:${hashId(ctx.sub)}`)).success;

  if (Array.isArray(bodyJson)) {
    if (bodyJson.length === 0) return Response.json(rpcErr(null, -32600, "Empty batch"), { status: 400 });
    if (bodyJson.length > MAX_BATCH) return Response.json(rpcErr(null, -32600, `Batch too large (max ${MAX_BATCH})`), { status: 400 });
    // Sequential, not Promise.all: a batch never fans out into parallel tool calls.
    const out: object[] = [];
    for (const m of bodyJson) {
      const r = await handleOne(m as RpcReq, tools, charge);
      if (r) out.push(r);
    }
    if (out.length === 0) return new Response(null, { status: 204 });
    return Response.json(out);
  }

  const res = await handleOne(bodyJson as RpcReq, tools, charge);
  if (res === null) return new Response(null, { status: 204 });
  return Response.json(res);
}
