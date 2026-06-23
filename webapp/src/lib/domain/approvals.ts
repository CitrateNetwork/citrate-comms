/**
 * HITL approvals (COMMS-CRM-DEPTH D3 / AGENTS-S1). Agent CRM writes do NOT mutate
 * directly — they ENQUEUE an approval capturing an executable action (encrypted), and
 * an Owner/Admin approves to apply it (or rejects). This is the human-in-the-loop gate
 * the guardrails require: the agent proposes, a human commits.
 *
 * The action payload is encrypted at rest; the inbox summary is DERIVED at read time
 * (never stored cleartext), so the approver sees what they're approving without
 * persisting PII in the open.
 */
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agentApprovals, agentToolCalls } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { logToolCall, finishToolCall } from "@/lib/ai/audit";
import { addNote } from "./crm-notes";
import { setFieldValue, listFieldDefs } from "./crm-fields";
import { updateAccount, updateDeal, updateContact } from "./crm";
import { recordActivity } from "./crm-activity";
import { getMemoryStore, neonMemoryStore, type MemoryAnchor, type TrustTier } from "@/lib/memory";
import { terminalExec, codeRun } from "@/lib/ai/runner";
import { ingestDocument } from "./documents";
import { witness, type WitnessKind } from "@/lib/witness/ledger";
import { createTask } from "./pm";
import type { CrmEntity, CrmNoteType } from "./crm-enums";

/** The executable spec stored (encrypted) on an approval and applied on approve. */
export type AgentAction =
  | { kind: "crm.note"; entity: CrmEntity; recordId: string; type: CrmNoteType; title?: string; body: string }
  | { kind: "crm.field"; entity: CrmEntity; recordId: string; fieldKey: string; value: string }
  | { kind: "crm.standard"; entity: CrmEntity; recordId: string; patch: { name?: string; domain?: string; title?: string; valueMinor?: number } }
  | { kind: "memory.assert"; repo: string; nodeKind: string; content: string; anchors?: MemoryAnchor[]; confidence?: number }
  | { kind: "runner.terminal"; cmd: string; cwd?: string }
  | { kind: "runner.code"; lang: "python" | "node" | "bash"; source: string; files?: { name: string; content: string }[] }
  | { kind: "documents.write"; name: string; content: string; accountId?: string; dealId?: string; channelId?: string }
  | { kind: "ledger.write"; channelId: string; ledgerKind: WitnessKind; text: string; owner?: string; due?: string }
  | { kind: "pm.write"; title: string; projectId?: string; priority?: "low" | "medium" | "high" };

export type Risk = "low" | "medium" | "high";

const RISK_BY_KIND: Record<AgentAction["kind"], Risk> = {
  "crm.note": "low",
  "crm.field": "medium",
  "crm.standard": "medium",
  "memory.assert": "low",
  "runner.terminal": "high",
  "runner.code": "high",
  "documents.write": "low",
  "ledger.write": "medium",
  "pm.write": "low",
};

export interface EnqueueArgs {
  workspaceId: string;
  tool: string;
  requestedBySub: string;
  personaId?: string | null;
  threadId?: string | null;
  action: AgentAction;
}

/** Queue an agent write for human approval. Returns the approval id + a short note. */
export async function enqueueApproval(args: EnqueueArgs): Promise<{ approvalId: string; risk: Risk }> {
  const risk = RISK_BY_KIND[args.action.kind];
  // Transparency log row (pending) — args are redacted by logToolCall.
  const toolCallId = await logToolCall(
    { workspaceId: args.workspaceId, threadId: args.threadId, personaId: args.personaId, invokedBySub: args.requestedBySub },
    args.tool,
    args.action,
    "pending",
  );
  const [row] = await db()
    .insert(agentApprovals)
    .values({
      workspaceId: args.workspaceId,
      toolCallId: toolCallId ?? (await fallbackToolCall(args)),
      tool: args.tool,
      risk,
      payloadEnc: encryptField(args.workspaceId, JSON.stringify(args.action)),
      requestedBySub: args.requestedBySub,
      personaId: args.personaId ?? null,
      status: "pending",
    })
    .returning({ id: agentApprovals.id });
  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.requestedBySub, event: "tool_pending_approval", target: `${args.tool}:${row!.id}` });
  return { approvalId: row!.id, risk };
}

/** If the tool-call log failed, still create a minimal row so the FK holds. */
async function fallbackToolCall(args: EnqueueArgs): Promise<string> {
  const [r] = await db()
    .insert(agentToolCalls)
    .values({ workspaceId: args.workspaceId, tool: args.tool, argsHash: "", argsRedacted: "[pending]", approvalStatus: "pending", invokedBySub: args.requestedBySub })
    .returning({ id: agentToolCalls.id });
  return r!.id;
}

export interface PendingApproval {
  id: string;
  tool: string;
  risk: Risk;
  requestedBySub: string;
  personaId: string | null;
  createdAt: string;
  summary: string; // derived at read — describes the proposed change
}

function describe(action: AgentAction): string {
  switch (action.kind) {
    case "crm.note":
      return `Add ${action.type} to ${action.entity}: ${truncate(action.title ? action.title + " — " + action.body : action.body)}`;
    case "crm.field":
      return `Set ${action.entity} field “${action.fieldKey}” = ${truncate(action.value)}`;
    case "crm.standard":
      return `Update ${action.entity}: ${truncate(JSON.stringify(action.patch))}`;
    case "memory.assert":
      return `Assert to knowledge graph (${action.nodeKind}): ${truncate(action.content)}`;
    case "runner.terminal":
      return `Run in sandbox: ${truncate(action.cmd)}`;
    case "runner.code":
      return `Run ${action.lang} in sandbox: ${truncate(action.source)}`;
    case "documents.write":
      return `Create document “${action.name}”: ${truncate(action.content)}`;
    case "ledger.write":
      return `File ${action.ledgerKind} to Ledger: ${truncate(action.text)}`;
    case "pm.write":
      return `Create task: ${truncate(action.title)}`;
  }
}
function truncate(s: string, n = 140): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

export async function listPendingApprovals(workspaceId: string): Promise<PendingApproval[]> {
  const rows = await db()
    .select()
    .from(agentApprovals)
    .where(and(eq(agentApprovals.workspaceId, workspaceId), eq(agentApprovals.status, "pending")))
    .orderBy(desc(agentApprovals.createdAt));
  return rows.map((r) => {
    let summary = "(unreadable)";
    if (r.payloadEnc) {
      try {
        summary = describe(JSON.parse(decryptField(workspaceId, r.payloadEnc)) as AgentAction);
      } catch {
        /* keep placeholder */
      }
    }
    return {
      id: r.id,
      tool: r.tool,
      risk: r.risk as Risk,
      requestedBySub: r.requestedBySub,
      personaId: r.personaId,
      createdAt: r.createdAt.toISOString(),
      summary,
    };
  });
}

export async function countPendingApprovals(workspaceId: string): Promise<number> {
  return (await listPendingApprovals(workspaceId)).length;
}

/** Approve (apply) or reject a queued agent action. Caller must hold the capability. */
export async function decideApproval(
  workspaceId: string,
  approvalId: string,
  decidedBy: string,
  decision: "approved" | "rejected",
): Promise<{ ok: boolean; error?: string }> {
  const [appr] = await db()
    .select()
    .from(agentApprovals)
    .where(and(eq(agentApprovals.workspaceId, workspaceId), eq(agentApprovals.id, approvalId)))
    .limit(1);
  if (!appr) return { ok: false, error: "not_found" };
  if (appr.status !== "pending") return { ok: false, error: "already_decided" };

  if (decision === "rejected") {
    await db().update(agentApprovals).set({ status: "rejected", decidedBySub: decidedBy, decidedAt: new Date() }).where(eq(agentApprovals.id, approvalId));
    await db().update(agentToolCalls).set({ approvalStatus: "rejected" }).where(eq(agentToolCalls.id, appr.toolCallId));
    await appendAudit({ workspaceId, actorSub: decidedBy, event: "tool_rejected", target: `${appr.tool}:${approvalId}` });
    return { ok: true };
  }

  // Approved → decrypt + execute.
  let action: AgentAction;
  try {
    action = JSON.parse(decryptField(workspaceId, appr.payloadEnc ?? "")) as AgentAction;
  } catch {
    return { ok: false, error: "bad_payload" };
  }
  let result: unknown;
  try {
    result = await executeAction(workspaceId, action, { bySub: appr.requestedBySub, personaId: appr.personaId });
  } catch {
    // Execution failed (e.g. runner unreachable) — keep it pending so it can be retried.
    return { ok: false, error: "execution_failed" };
  }
  await db().update(agentApprovals).set({ status: "approved", decidedBySub: decidedBy, decidedAt: new Date() }).where(eq(agentApprovals.id, approvalId));
  await db().update(agentToolCalls).set({ approvalStatus: "approved" }).where(eq(agentToolCalls.id, appr.toolCallId));
  await finishToolCall(appr.toolCallId, result);
  await appendAudit({ workspaceId, actorSub: decidedBy, event: "tool_approved", target: `${appr.tool}:${approvalId}` });
  return { ok: true };
}

async function executeAction(
  workspaceId: string,
  action: AgentAction,
  by: { bySub: string; personaId: string | null },
): Promise<unknown> {
  switch (action.kind) {
    case "crm.note": {
      const note = await addNote({
        workspaceId,
        entity: action.entity,
        recordId: action.recordId,
        type: action.type,
        title: action.title ?? null,
        body: action.body,
        authorSub: by.bySub,
        byAgent: true,
        personaId: by.personaId,
      });
      return { noteId: note.id };
    }
    case "crm.field": {
      const defs = await listFieldDefs(workspaceId, action.entity, { includeDisabled: true });
      const def = defs.find((d) => d.key === action.fieldKey);
      if (!def) throw new Error(`unknown field ${action.fieldKey}`);
      await setFieldValue({ workspaceId, entity: action.entity, recordId: action.recordId, fieldId: def.id, raw: action.value, bySub: by.bySub, byAgent: true });
      return { field: action.fieldKey };
    }
    case "crm.standard": {
      if (action.entity === "account") await updateAccount(workspaceId, action.recordId, { name: action.patch.name, domain: action.patch.domain }, by.bySub);
      else if (action.entity === "deal") await updateDeal(workspaceId, action.recordId, { name: action.patch.name, valueMinor: action.patch.valueMinor }, by.bySub);
      else await updateContact(workspaceId, action.recordId, { name: action.patch.name, title: action.patch.title }, by.bySub);
      await recordActivity({ workspaceId, entity: action.entity, recordId: action.recordId, actorSub: by.bySub, byAgent: true, input: { kind: "agent_action", tool: "crm.write" } });
      return { updated: true };
    }
    case "memory.assert": {
      const input = {
        kind: action.nodeKind,
        content: action.content,
        anchors: action.anchors,
        confidence: action.confidence,
        trustTier: "agent-asserted" as TrustTier,
      };
      let node;
      try {
        node = await (await getMemoryStore()).assert(action.repo, input, { workspaceId, sub: by.bySub });
      } catch {
        node = await neonMemoryStore().assert(action.repo, input, { workspaceId, sub: by.bySub });
      }
      return { nodeId: node.id };
    }
    case "runner.terminal":
      return terminalExec(action.cmd, action.cwd);
    case "runner.code":
      return codeRun(action.lang, action.source, action.files);
    case "documents.write": {
      const res = await ingestDocument({
        workspaceId,
        scope: { accountId: action.accountId, dealId: action.dealId, channelId: action.channelId },
        name: action.name,
        mime: "text/markdown",
        blobUrl: "",
        uploadedBySub: by.bySub,
        text: action.content,
      });
      return { documentId: res.id, chunks: res.chunks };
    }
    case "ledger.write": {
      const entry = await witness({
        workspaceId,
        channelId: action.channelId,
        kind: action.ledgerKind,
        text: action.text,
        bySub: by.bySub,
        ownerSub: action.owner,
        due: action.due ? new Date(action.due) : null,
        proposedByAgent: true,
      });
      return { ledgerId: entry.id };
    }
    case "pm.write": {
      const task = await createTask({ workspaceId, projectId: action.projectId ?? null, title: action.title, priority: action.priority ?? null });
      return { taskId: task.id };
    }
  }
}
