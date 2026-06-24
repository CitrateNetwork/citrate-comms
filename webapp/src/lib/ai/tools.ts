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
import { retrieveChunks } from "@/lib/domain/documents";
import { listMessages } from "@/lib/domain/messages";
import { listTasks, listProjects } from "@/lib/domain/pm";
import { webSearch, webFetch, chartRender, RunnerUnavailableError } from "./runner";
import { searchWeb } from "@/lib/research/search";
import { fetchReadable } from "@/lib/research/fetch";
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
  /** When false (incognito), tool calls are NOT written to the transparency log. Default true. */
  audit?: boolean;
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

  const audit = ctx.audit !== false;
  const audited =
    <A>(name: ToolName, cap: Capability, run: (args: A) => Promise<unknown>) =>
    async (args: A) => {
      // Fail-closed RBAC: the agent's role must hold the capability.
      if (!can(ctx.agentRole, cap)) throw new ToolDenied(`role ${ctx.agentRole} may not ${name}`);
      if (!audit) return run(args); // incognito: no transparency-log row
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

    // ── Documents + notetaker tools (BFF inline reads; writes are HITL-gated; S4) ──
    "documents.read": tool({
      description:
        "Retrieve from the team's uploaded documents (RAG). Returns cited snippets with their source " +
        "document name. Use to ground answers in real files — cite what you used.",
      inputSchema: z.object({ query: z.string().min(1).max(400), budget: z.number().int().min(1).max(10).default(6) }),
      execute: audited("documents.read", Capability.ReadChannel, async (a: { query: string; budget: number }) => {
        const results = await retrieveChunks(ctx.workspaceId, a.query, { budget: a.budget });
        return { results: results.map((r) => ({ document: r.name, snippet: r.snippet })) };
      }),
    }),
    "pm.read": tool({
      description: "Read projects and tasks (the board). Optionally scope to a project. Returns real records.",
      inputSchema: z.object({ projectId: z.string().uuid().optional() }),
      execute: audited("pm.read", Capability.ReadChannel, async (a: { projectId?: string }) => {
        const [projects, tasks] = await Promise.all([listProjects(ctx.workspaceId), listTasks(ctx.workspaceId, a.projectId)]);
        return { projects, tasks: tasks.map((t) => ({ id: t.id, title: t.title, status: t.status, priority: t.priority, projectId: t.projectId })) };
      }),
    }),
    "thread.summarize": tool({
      description:
        "Read a channel's recent messages so you can summarize them and extract action items. Returns the " +
        "messages (oldest→newest). Use before filing notes/decisions/tasks.",
      inputSchema: z.object({ channelId: z.string().uuid(), limit: z.number().int().min(1).max(200).default(50) }),
      execute: audited("thread.summarize", Capability.ReadChannel, async (a: { channelId: string; limit: number }) => {
        const msgs = await listMessages(ctx.workspaceId, a.channelId, { limit: a.limit });
        return { messages: msgs.map((m) => ({ author: m.authorSub, body: m.body, at: m.createdAt })) };
      }),
    }),
    "documents.write": tool({
      description:
        "Propose creating a document/report (e.g. meeting notes, an analysis writeup) attached to the " +
        "workspace or a record. HITL: queued for approval, then stored + indexed for RAG.",
      inputSchema: z.object({
        name: z.string().min(1).max(160),
        content: z.string().min(1).max(50000),
        accountId: z.string().uuid().optional(),
        dealId: z.string().uuid().optional(),
        channelId: z.string().uuid().optional(),
      }),
      execute: async (a: { name: string; content: string; accountId?: string; dealId?: string; channelId?: string }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "documents.write",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "documents.write", name: a.name, content: a.content, accountId: a.accountId, dealId: a.dealId, channelId: a.channelId },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval." };
      },
    }),
    "ledger.write": tool({
      description:
        "Propose filing a decision/commitment/resolution into the witness Ledger for a channel (the " +
        "signature audit feature). HITL: queued for human approval.",
      inputSchema: z.object({
        channelId: z.string().uuid(),
        kind: z.enum(["decision", "commitment", "resolved"]),
        text: z.string().min(1).max(2000),
        owner: z.string().max(120).optional(),
        due: z.string().datetime().optional(),
      }),
      execute: async (a: { channelId: string; kind: "decision" | "commitment" | "resolved"; text: string; owner?: string; due?: string }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "ledger.write",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "ledger.write", channelId: a.channelId, ledgerKind: a.kind, text: a.text, owner: a.owner, due: a.due },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval." };
      },
    }),
    "pm.write": tool({
      description: "Propose creating a task on the board. HITL: queued for human approval.",
      inputSchema: z.object({
        title: z.string().min(1).max(200),
        projectId: z.string().uuid().optional(),
        priority: z.enum(["low", "medium", "high"]).optional(),
      }),
      execute: async (a: { title: string; projectId?: string; priority?: "low" | "medium" | "high" }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "pm.write",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "pm.write", title: a.title, projectId: a.projectId, priority: a.priority },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval." };
      },
    }),

    // ── Runner tools (delegated to the comms-agent-runner; S3) ──
    // Reads run inline; terminal/code are HITL-gated (propose → approve → run).
    "web.search": tool({
      description: "Search the live web via the agent runner. Returns cited results (title, url, snippet). Use for company/market research; cite every external claim.",
      inputSchema: z.object({ query: z.string().min(1).max(400), k: z.number().int().min(1).max(10).default(5) }),
      execute: audited("web.search", Capability.ReadChannel, async (a: { query: string; k: number }) => {
        // RES: keyless BFF search first (SearXNG → DuckDuckGo). Fall back to the runner only
        // if the BFF has nothing configured/reachable AND a runner is present.
        const bff = await searchWeb(a.query, a.k);
        if (bff.available) return bff;
        try {
          return await webSearch(a.query, a.k);
        } catch (e) {
          if (e instanceof RunnerUnavailableError) return bff; // keep the BFF "unavailable" note
          throw e;
        }
      }),
    }),
    "web.fetch": tool({
      description: "Fetch and extract the readable text of a web page via the runner. Use after web.search to read a source.",
      inputSchema: z.object({ url: z.string().url() }),
      execute: audited("web.fetch", Capability.ReadChannel, async (a: { url: string }) => {
        // RES: SSRF-guarded static fetch + readability on the BFF. Escalate to the runner's
        // Playwright path only when the static extraction yields no usable text (JS-heavy).
        const page = await fetchReadable(a.url);
        if (page.available && page.text.length > 200) return page;
        try {
          const dyn = await webFetch(a.url);
          if (dyn && typeof dyn.text === "string" && dyn.text.length > 0) return { ...dyn, available: true };
        } catch (e) {
          if (!(e instanceof RunnerUnavailableError)) throw e;
        }
        // No runner (or it failed): return whatever static gave us, honestly flagged.
        return page.available ? page : { url: a.url, title: "", text: "", available: false, note: page.note };
      }),
    }),
    "chart.render": tool({
      description: "Render a chart artifact from a spec via the runner; returns a URL to embed in a report.",
      inputSchema: z.object({ spec: z.record(z.string(), z.unknown()).describe("a chart spec (e.g. vega-lite-ish)") }),
      execute: audited("chart.render", Capability.ReadChannel, async (a: { spec: Record<string, unknown> }) => {
        try {
          return await chartRender(a.spec);
        } catch (e) {
          if (e instanceof RunnerUnavailableError) return { url: null, available: false, note: "Chart rendering is unavailable (agent runner not configured)." };
          throw e;
        }
      }),
    }),
    "terminal.exec": tool({
      description: "Propose running an allow-listed shell command in the runner's capsule sandbox. HITL: queued for human approval, then executed in the sandbox. Use for read-only inspection of exported data.",
      inputSchema: z.object({ cmd: z.string().min(1).max(2000), cwd: z.string().max(400).optional() }),
      execute: async (a: { cmd: string; cwd?: string }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "terminal.exec",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "runner.terminal", cmd: a.cmd, cwd: a.cwd },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval before it runs in the sandbox." };
      },
    }),
    "code.run": tool({
      description: "Propose running code over exported CRM data in the runner's sandbox. HITL: queued for human approval, then executed; returns stdout + artifacts. Prefer reproducible analyses.",
      inputSchema: z.object({
        lang: z.enum(["python", "node", "bash"]),
        source: z.string().min(1).max(20000),
        files: z.array(z.object({ name: z.string().max(120), content: z.string().max(100000) })).max(10).optional(),
      }),
      execute: async (a: { lang: "python" | "node" | "bash"; source: string; files?: { name: string; content: string }[] }) => {
        const { approvalId, risk } = await enqueueApproval({
          workspaceId: ctx.workspaceId,
          tool: "code.run",
          requestedBySub: ctx.invokedBySub,
          personaId: ctx.personaId,
          threadId: ctx.threadId,
          action: { kind: "runner.code", lang: a.lang, source: a.source, files: a.files },
        });
        return { status: "pending_approval", approvalId, risk, message: "Queued for human approval before it runs in the sandbox." };
      },
    }),
  };

  // Filter to the persona allow-list (if provided) — implemented tools only.
  const entries = Object.entries(all).filter(([key]) => !ctx.allow || ctx.allow.has(key as ToolName));
  return Object.fromEntries(entries) as Partial<typeof all>;
}

/** Tool names the registry currently IMPLEMENTS (others are declared but not yet live). */
export const IMPLEMENTED_TOOLS: ToolName[] = [
  "crm.read",
  "crm.write",
  "crm.note",
  "pm.read",
  "pm.write",
  "ledger.write",
  "thread.summarize",
  "memory.recall",
  "memory.assert",
  "documents.read",
  "documents.write",
  "web.search",
  "web.fetch",
  "terminal.exec",
  "code.run",
  "chart.render",
];
