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
import { getAccountFile, getDealFile, getContactFile, type RecordFile } from "@/lib/domain/crm-file";
import { enqueueApproval } from "@/lib/domain/approvals";
import type { CrmEntity } from "@/lib/domain/crm-enums";
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
  /** Custom field keys per entity — injected so crm.write advertises valid keys (dynamic schema). */
  fieldDefsByEntity?: Partial<Record<CrmEntity, { key: string; label: string; type: string }[]>>;
}

const entitySchema = z.enum(["account", "deal", "contact"]);

/** Compact a full record file for the model (drop heavy doc/memory blobs). */
function compactFile(file: RecordFile) {
  return {
    entity: file.entity,
    id: file.recordId,
    title: file.title,
    subtitle: file.subtitle,
    stats: file.headerStats,
    fields: file.fields.filter((f) => f.value != null && f.value !== "").map((f) => ({ label: f.def.label, key: f.def.key, value: f.value })),
    tags: file.tags.map((t) => t.label),
    recentNotes: file.notes.slice(0, 5).map((n) => ({ type: n.type, title: n.title, body: n.body, at: n.createdAt })),
    recentActivity: file.activity.slice(0, 8).map((a) => a.summary),
    related: file.related.map((g) => ({ label: g.label, items: g.items.map((i) => ({ id: i.id, name: i.name, entity: i.entity })) })),
  };
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
        "Read CRM records. With an `id`, returns that record's FULL FILE (standard + custom fields, " +
        "recent notes/journal, recent activity, tags, related records). Without an `id`, lists records " +
        "(filter by name `query`). Returns real records — never invent CRM data.",
      inputSchema: z.object({
        entity: entitySchema.describe("which CRM entity to read"),
        id: z.string().uuid().optional().describe("a specific record id → returns its full file"),
        query: z.string().max(200).optional().describe("case-insensitive substring match on name (list mode)"),
        limit: z.number().int().min(1).max(50).default(20),
      }),
      execute: audited(
        "crm.read",
        Capability.ReadChannel,
        async (a: { entity: CrmEntity; id?: string; query?: string; limit: number }) => {
          if (a.id) {
            const file =
              a.entity === "account"
                ? await getAccountFile(ctx.workspaceId, a.id)
                : a.entity === "deal"
                  ? await getDealFile(ctx.workspaceId, a.id)
                  : await getContactFile(ctx.workspaceId, a.id);
            return file ? { record: compactFile(file) } : { error: "record not found" };
          }
          const q = a.query?.toLowerCase();
          const match = <T extends { id: string; name: string }>(rows: T[]) =>
            rows.filter((r) => (q ? r.name.toLowerCase().includes(q) : true)).slice(0, a.limit);
          if (a.entity === "account") return { accounts: match(await listAccounts(ctx.workspaceId)) };
          if (a.entity === "deal") return { deals: match(await listDeals(ctx.workspaceId)) };
          return { contacts: match(await listContacts(ctx.workspaceId)) };
        },
      ),
    }),

    // ── Mutating CRM tools — PROPOSE only; queued for human approval (HITL) ──
    "crm.note": tool({
      description:
        "Propose adding a note/journal/call/meeting/email entry to a CRM record. This does NOT apply " +
        "immediately — it is queued for a human to approve. Use to log meeting summaries, call notes, and " +
        "follow-ups onto the record's file.",
      inputSchema: z.object({
        entity: entitySchema,
        recordId: z.string().uuid(),
        type: z.enum(["note", "journal", "call", "meeting", "email"]).default("note"),
        title: z.string().max(200).optional(),
        body: z.string().min(1).max(8000),
      }),
      execute: async (a: { entity: CrmEntity; recordId: string; type: "note" | "journal" | "call" | "meeting" | "email"; title?: string; body: string }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "crm.note",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "crm.note", entity: a.entity, recordId: a.recordId, type: a.type, title: a.title, body: a.body },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval — it will be applied once an admin approves." };
      },
    }),

    "crm.write": tool({
      description:
        "Propose setting fields on a CRM record (queued for human approval — NOT applied immediately). " +
        "Provide `standard` (name; domain for account; value in USD for deal; title for contact) and/or " +
        "`fields` (custom field key/value pairs). Available custom field keys — " +
        `account: [${(ctx.fieldDefsByEntity?.account ?? []).map((d) => d.key).join(", ") || "none"}]; ` +
        `deal: [${(ctx.fieldDefsByEntity?.deal ?? []).map((d) => d.key).join(", ") || "none"}]; ` +
        `contact: [${(ctx.fieldDefsByEntity?.contact ?? []).map((d) => d.key).join(", ") || "none"}].`,
      inputSchema: z.object({
        entity: entitySchema,
        recordId: z.string().uuid(),
        standard: z
          .object({
            name: z.string().max(160).optional(),
            domain: z.string().max(160).optional(),
            title: z.string().max(160).optional(),
            value: z.number().min(0).optional(),
          })
          .optional(),
        fields: z.array(z.object({ key: z.string().max(60), value: z.string().max(8000) })).max(30).optional(),
      }),
      execute: async (a: { entity: CrmEntity; recordId: string; standard?: { name?: string; domain?: string; title?: string; value?: number }; fields?: { key: string; value: string }[] }) => {
        const approvalIds: string[] = [];
        if (a.standard && Object.values(a.standard).some((v) => v !== undefined)) {
          const patch = {
            name: a.standard.name,
            domain: a.standard.domain,
            title: a.standard.title,
            valueMinor: a.standard.value != null ? Math.round(a.standard.value * 100) : undefined,
          };
          const { approvalId } = await enqueueApproval({
            workspaceId: ctx.workspaceId,
            tool: "crm.write",
            requestedBySub: ctx.invokedBySub,
            personaId: ctx.personaId,
            threadId: ctx.threadId,
            action: { kind: "crm.standard", entity: a.entity, recordId: a.recordId, patch },
          });
          approvalIds.push(approvalId);
        }
        for (const f of a.fields ?? []) {
          const { approvalId } = await enqueueApproval({
            workspaceId: ctx.workspaceId,
            tool: "crm.write",
            requestedBySub: ctx.invokedBySub,
            personaId: ctx.personaId,
            threadId: ctx.threadId,
            action: { kind: "crm.field", entity: a.entity, recordId: a.recordId, fieldKey: f.key, value: f.value },
          });
          approvalIds.push(approvalId);
        }
        if (approvalIds.length === 0) return { status: "noop", message: "Nothing to change." };
        return { status: "pending_approval", queued: approvalIds.length, approvalIds, message: "Queued for human approval." };
      },
    }),

    "memory.assert": tool({
      description:
        "Propose asserting a durable finding to the workspace knowledge graph (Asserted plane — signed + " +
        "trust-tiered). This does NOT apply immediately; it is queued for human approval. Use for facts worth " +
        "remembering about accounts/deals/contacts (preferences, risks, commitments). Anchor it to the record(s).",
      inputSchema: z.object({
        kind: z.string().min(1).max(60).describe("finding kind, e.g. preference | risk | fact | commitment"),
        content: z.string().min(1).max(4000),
        anchors: z
          .array(z.object({ entity: z.string().max(40), id: z.string().max(80) }))
          .max(10)
          .optional()
          .describe("entity anchors this finding is about"),
        confidence: z.number().int().min(0).max(100).optional(),
      }),
      execute: async (a: { kind: string; content: string; anchors?: { entity: string; id: string }[]; confidence?: number }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "memory.assert",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "memory.assert", repo: crmRepo(ctx.workspaceId), nodeKind: a.kind, content: a.content, anchors: a.anchors, confidence: a.confidence },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval before it joins the knowledge graph." };
      },
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
export const IMPLEMENTED_TOOLS: ToolName[] = ["crm.read", "memory.recall", "memory.assert", "crm.note", "crm.write"];
