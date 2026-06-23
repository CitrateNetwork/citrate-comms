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
import { requireMember, GuardError } from "@/lib/tenant/guard";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { citrateCommsTools } from "@/lib/ai/tools";
import { IMPLEMENTED_TOOLS } from "@/lib/ai/tools";

export const runtime = "nodejs";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "citrate-comms-agents", version: "0.1.0" };

interface McpTool {
  description?: string;
  inputSchema: z.ZodType;
  execute: (args: unknown) => Promise<unknown>;
}
type Json = Record<string, unknown>;

function buildTools(workspaceId: string, sub: string) {
  return citrateCommsTools({
    workspaceId,
    invokedBySub: sub,
    agentRole: "Agent",
    allow: new Set(IMPLEMENTED_TOOLS),
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

async function handleOne(msg: RpcReq, tools: Record<string, McpTool>): Promise<object | null> {
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
      try {
        const result = await t.execute(parsed.data);
        return rpcOk(id, { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result as Json, isError: false });
      } catch (err) {
        const message = (err as Error)?.message ?? "tool execution failed";
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
    const tools = buildTools(id, ctx.sub);
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
  let sub: string;
  try {
    const { id } = await params;
    workspaceId = id;
    const ctx = await requireMember(req, workspaceId);
    sub = ctx.sub;
  } catch (e) {
    if (e instanceof GuardError) return Response.json(rpcErr(null, -32000, e.message), { status: e.status });
    return Response.json(rpcErr(null, -32603, "internal error"), { status: 500 });
  }

  const rl = await limit(`mcp:${hashId(sub)}`);
  if (!rl.success) {
    return Response.json(rpcErr(null, -32000, "Rate limit exceeded"), { status: 429 });
  }

  const tools = buildTools(workspaceId, sub);

  let bodyJson: unknown;
  try {
    bodyJson = await req.json();
  } catch {
    return Response.json(rpcErr(null, -32700, "Parse error"), { status: 400 });
  }

  if (Array.isArray(bodyJson)) {
    if (bodyJson.length === 0) return Response.json(rpcErr(null, -32600, "Empty batch"), { status: 400 });
    const out = (await Promise.all(bodyJson.map((m) => handleOne(m as RpcReq, tools)))).filter(Boolean);
    if (out.length === 0) return new Response(null, { status: 204 });
    return Response.json(out);
  }

  const res = await handleOne(bodyJson as RpcReq, tools);
  if (res === null) return new Response(null, { status: 204 });
  return Response.json(res);
}
