/**
 * The comms agent tool registry — the SINGLE SOURCE OF TRUTH for what an agent can
 * do (COMMS-AGENTS build-spec §4). Mirrors `citrate-explorer/src/lib/ai/tools.ts`:
 * every tool is `tool({ description, inputSchema: z.object(...), execute: audited(...) })`.
 * The same registry is served at `/api/.../mcp` (JSON-RPC 2.0) — no drift.
 *
 * `audited()` writes the call to the transparency log + audit chain BEFORE execution
 * (args truncated/hashed/redacted). Every tool re-checks RBAC for the agent's role;
 * write/terminal tools additionally pass the HITL gate (later sprints). S0 implements
 * the read pair the chat route needs — `crm.read` + `memory.recall` — with the rest of
 * the v1 vocabulary declared in personas.ts so they light up without persona churn.
 */
import { tool } from "ai";
import { z } from "zod";
import { Capability, can, type Role } from "@/lib/rbac/matrix";
import { listAccounts, listDeals, listContacts } from "@/lib/domain/crm";
import { getMemoryStore, neonMemoryStore, crmRepo, type TrustTier } from "@/lib/memory";
import { logToolCall, finishToolCall, type ToolAuditCtx } from "./audit";
import type { ToolName } from "./personas";

export interface ToolContext {
  workspaceId: string;
  invokedBySub: string;
  personaId?: string | null;
  threadId?: string | null;
  /** The agent member's role — bounds what the registry permits (role=Agent). */
  agentRole: Role;
  /** The persona's tool allow-list. Omitted ⇒ all IMPLEMENTED tools (e.g. MCP). */
  allow?: Set<ToolName>;
}

class ToolDenied extends Error {}

const trustTierSchema = z
  .enum(["derived-deterministic", "human-confirmed", "agent-asserted", "inferred-advisory"])
  .describe("minimum trust tier to include (strongest→weakest)");

/**
 * Build the tool map for a turn. `audited` logs + chains every call; RBAC is checked
 * per tool. Only tools that are (a) implemented and (b) in the persona allow-list (if
 * provided) are returned to the model.
 */
export function citrateCommsTools(ctx: ToolContext) {
  const auditCtx: ToolAuditCtx = {
    workspaceId: ctx.workspaceId,
    threadId: ctx.threadId,
    personaId: ctx.personaId,
    invokedBySub: ctx.invokedBySub,
  };

  const audited =
    <A>(name: ToolName, cap: Capability, run: (args: A) => Promise<unknown>) =>
    async (args: A) => {
      // Fail-closed RBAC: the agent's role must hold the capability.
      if (!can(ctx.agentRole, cap)) throw new ToolDenied(`role ${ctx.agentRole} may not ${name}`);
      const id = await logToolCall(auditCtx, name, args, "auto");
      try {
        const result = await run(args);
        await finishToolCall(id, result);
        return result;
      } catch (err) {
        await finishToolCall(id, { error: (err as Error)?.message ?? "tool error" });
        throw err;
      }
    };

  const all = {
    "crm.read": tool({
      description:
        "Read CRM records (accounts, deals, or contacts) in this workspace. Filter by id or a " +
        "case-insensitive name query. Returns real records — never invent CRM data.",
      inputSchema: z.object({
        entity: z.enum(["account", "deal", "contact"]).describe("which CRM entity to read"),
        id: z.string().uuid().optional().describe("a specific record id"),
        query: z.string().max(200).optional().describe("case-insensitive substring match on name"),
        limit: z.number().int().min(1).max(50).default(20),
      }),
      execute: audited(
        "crm.read",
        Capability.ReadChannel,
        async (a: { entity: "account" | "deal" | "contact"; id?: string; query?: string; limit: number }) => {
          const q = a.query?.toLowerCase();
          const match = <T extends { id: string; name: string }>(rows: T[]) =>
            rows
              .filter((r) => (a.id ? r.id === a.id : true))
              .filter((r) => (q ? r.name.toLowerCase().includes(q) : true))
              .slice(0, a.limit);
          if (a.entity === "account") return { accounts: match(await listAccounts(ctx.workspaceId)) };
          if (a.entity === "deal") return { deals: match(await listDeals(ctx.workspaceId)) };
          return { contacts: match(await listContacts(ctx.workspaceId)) };
        },
      ),
    }),

    "memory.recall": tool({
      description:
        "Recall facts from this workspace's knowledge graph. Returns items with their TRUST TIER " +
        "and provenance — cite them and weight by tier. Use before asserting anything as known.",
      inputSchema: z.object({
        query: z.string().min(1).max(400).describe("what to recall"),
        trustFloor: trustTierSchema.optional(),
        budget: z.number().int().min(1).max(20).default(6).describe("max items to return"),
        anchors: z
          .array(z.object({ entity: z.string().max(40), id: z.string().max(80) }))
          .max(10)
          .optional()
          .describe("optional entity anchors to focus the recall"),
      }),
      execute: audited(
        "memory.recall",
        Capability.ReadChannel,
        async (a: { query: string; trustFloor?: TrustTier; budget: number; anchors?: { entity: string; id: string }[] }) => {
          const repo = crmRepo(ctx.workspaceId);
          const q = { query: a.query, trustFloor: a.trustFloor, budget: a.budget, anchors: a.anchors };
          let res;
          try {
            res = await (await getMemoryStore()).recall(repo, q);
          } catch {
            // Gateway hiccup mid-flight → degrade to the Neon fallback (decision #4).
            res = await neonMemoryStore().recall(repo, q);
          }
          return {
            source: res.source,
            items: res.items.map((m) => ({
              id: m.id,
              kind: m.kind,
              content: m.content,
              trustTier: m.trustTier,
              confidence: m.confidence,
              anchors: m.anchors,
            })),
          };
        },
      ),
    }),
  };

  // Filter to the persona allow-list (if provided) — implemented tools only.
  const entries = Object.entries(all).filter(([key]) => !ctx.allow || ctx.allow.has(key as ToolName));
  return Object.fromEntries(entries) as Partial<typeof all>;
}

/** Tool names the registry currently IMPLEMENTS (others are declared but not yet live). */
export const IMPLEMENTED_TOOLS: ToolName[] = ["crm.read", "memory.recall"];
