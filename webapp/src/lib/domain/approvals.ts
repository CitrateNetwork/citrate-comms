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
import { can, Capability, type Role } from "@/lib/rbac/matrix";
import { GuardError } from "@/lib/tenant/guard";
import { appendAudit } from "@/lib/audit/chain";
import { logToolCall, finishToolCall } from "@/lib/ai/audit";
import { addNote } from "./crm-notes";
import { setFieldValue, listFieldDefs } from "./crm-fields";
import { updateAccount, updateDeal, updateContact, upsertAccount, upsertDeal, upsertContact, deleteAccount, deleteDeal, deleteContact } from "./crm";
import { dedupeWorkspaceCrm } from "./crm-dedupe";
import { createEvent, cancelEvent } from "./calendar";
import { recordActivity } from "./crm-activity";
import { getMemoryStore, neonMemoryStore, type MemoryAnchor, type TrustTier } from "@/lib/memory";
import { terminalExec, codeRun } from "@/lib/ai/runner";
import { ingestDocument } from "./documents";
import { witness, type WitnessKind } from "@/lib/witness/ledger";
import { createTask, setTaskRaci } from "./pm";
import { approveMapping, createImportJob, runImportSlice, flushHeldRows, type PreviewCounts } from "./import-engine";
import type { CrmEntity, CrmNoteType } from "./crm-enums";

/** The executable spec stored (encrypted) on an approval and applied on approve. */
export type AgentAction =
  | { kind: "crm.note"; entity: CrmEntity; recordId: string; type: CrmNoteType; title?: string; body: string }
  | { kind: "crm.field"; entity: CrmEntity; recordId: string; fieldKey: string; value: string }
  | { kind: "crm.standard"; entity: CrmEntity; recordId: string; patch: { name?: string; domain?: string; title?: string; valueMinor?: number } }
  | { kind: "crm.create"; entity: CrmEntity; standard: { name: string; domain?: string; title?: string; valueMinor?: number }; accountId?: string; fields?: { key: string; value: string }[] }
  | { kind: "crm.delete"; entity: CrmEntity; recordId: string }
  | { kind: "crm.dedupe" }
  | { kind: "memory.assert"; repo: string; nodeKind: string; content: string; anchors?: MemoryAnchor[]; confidence?: number }
  | { kind: "runner.terminal"; cmd: string; cwd?: string }
  | { kind: "runner.code"; lang: "python" | "node" | "bash"; source: string; files?: { name: string; content: string }[] }
  | { kind: "documents.write"; name: string; content: string; accountId?: string; dealId?: string; channelId?: string }
  | { kind: "ledger.write"; channelId: string; ledgerKind: WitnessKind; text: string; owner?: string; due?: string }
  | { kind: "pm.write"; title: string; projectId?: string; priority?: "low" | "medium" | "high"; assigneeSub?: string; due?: string; raci?: { sub: string; role: "R" | "A" | "C" | "I" }[] }
  | { kind: "crm.import"; sheetId: string; mappingId: string; sheetName: string; preview: PreviewCounts }
  | { kind: "crm.ingest_review"; jobId: string; sheetName: string; held: number }
  | { kind: "calendar.schedule"; title: string; eventKind: "meeting" | "deadline" | "focus"; startsAt: string; endsAt: string; timezone: string; location?: string; description?: string; attendees?: { sub: string; raciRole: "R" | "A" | "C" | "I" | null }[]; channelId?: string }
  | { kind: "calendar.cancel"; eventId: string };

export type Risk = "low" | "medium" | "high";

const RISK_BY_KIND: Record<AgentAction["kind"], Risk> = {
  "crm.note": "low",
  "crm.field": "medium",
  "crm.standard": "medium",
  "crm.create": "medium",
  "crm.delete": "high",
  "crm.dedupe": "high",
  "memory.assert": "low",
  "runner.terminal": "high",
  "runner.code": "high",
  "documents.write": "low",
  "ledger.write": "medium",
  "pm.write": "low",
  "crm.import": "high",
  "crm.ingest_review": "high",
  "calendar.schedule": "medium",
  "calendar.cancel": "medium",
};

/**
 * CM2-B-B004 / CIT-COMMS-002: the capability an approver must hold to APPROVE each
 * action kind — pinned to the capability the SAME mutation requires on its direct
 * route, so the approval queue can never be a lower-privileged path to a privileged
 * op. `crm.delete`/`crm.dedupe` need DeleteRecord (Owner/Admin, as the direct CRM
 * delete route does); the sandbox runner (arbitrary shell / code) and bulk imports
 * need ManageWorkspace (Owner/Admin). Everything else stays at CreateRecord (Member).
 */
const CAP_BY_KIND: Record<AgentAction["kind"], Capability> = {
  "crm.note": Capability.CreateRecord,
  "crm.field": Capability.CreateRecord,
  "crm.standard": Capability.CreateRecord,
  "crm.create": Capability.CreateRecord,
  "crm.delete": Capability.DeleteRecord,
  "crm.dedupe": Capability.DeleteRecord,
  "memory.assert": Capability.CreateRecord,
  "runner.terminal": Capability.ManageWorkspace,
  "runner.code": Capability.ManageWorkspace,
  "documents.write": Capability.CreateRecord,
  "ledger.write": Capability.CreateRecord,
  "pm.write": Capability.CreateRecord,
  "crm.import": Capability.ManageWorkspace,
  "crm.ingest_review": Capability.ManageWorkspace,
  "calendar.schedule": Capability.CreateRecord,
  "calendar.cancel": Capability.CreateRecord,
};

/**
 * Why an approver may NOT decide this action, or null if permitted. Pure so it is
 * unit-testable without a database. Enforces (a) the per-kind capability re-check
 * against the APPROVER's role, and (b) no self-approval of a high-risk action (the
 * proposer must not also be the sole human committing it — separation of duties).
 */
export function approvalAuthzError(
  role: Role,
  action: AgentAction,
  decidedBy: string,
  requestedBy: string,
): "forbidden" | "self_approval_forbidden" | null {
  if (!can(role, CAP_BY_KIND[action.kind])) return "forbidden";
  if (RISK_BY_KIND[action.kind] === "high" && decidedBy === requestedBy) return "self_approval_forbidden";
  return null;
}

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
    { redactBody: true }, // body lives only in the encrypted payloadEnc (CM2-B-B016)
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

export function describeAction(action: AgentAction): string {
  switch (action.kind) {
    case "crm.note":
      return `Add ${action.type} to ${action.entity}: ${truncate(action.title ? action.title + " — " + action.body : action.body)}`;
    case "crm.field":
      return `Set ${action.entity} field “${action.fieldKey}” = ${truncate(action.value)}`;
    case "crm.standard":
      return `Update ${action.entity}: ${truncate(JSON.stringify(action.patch))}`;
    case "crm.create":
      return `Create ${action.entity} “${truncate(action.standard.name, 80)}”${action.fields?.length ? ` (+${action.fields.length} fields)` : ""}`;
    case "crm.delete":
      return `Delete ${action.entity} (id ${action.recordId.slice(0, 8)}…) and its notes/fields/activity`;
    case "crm.dedupe":
      return `De-duplicate the CRM — merge duplicate accounts/deals/contacts into one canonical each`;
    case "memory.assert":
      return `Assert to knowledge graph (${action.nodeKind}): ${truncate(action.content)}`;
    // CM2-B-B005: high-risk sandbox execution is shown IN FULL (never truncated), so
    // the human consents to exactly what runs — a 140-char preview of a 20k-char
    // payload is consent to a different thing. Byte count + file manifest included.
    case "runner.terminal":
      return `Run in sandbox (${Buffer.byteLength(action.cmd)} bytes):\n${action.cmd}`;
    case "runner.code": {
      const files = action.files?.length
        ? `\nfiles: ${action.files.map((f) => `${f.name} (${Buffer.byteLength(f.content)}B)`).join(", ")}`
        : "";
      return `Run ${action.lang} in sandbox (${Buffer.byteLength(action.source)} bytes):\n${action.source}${files}`;
    }
    case "documents.write":
      return `Create document “${action.name}”: ${truncate(action.content)}`;
    case "ledger.write":
      return `File ${action.ledgerKind} to Ledger: ${truncate(action.text)}`;
    case "pm.write":
      return `Create task: ${truncate(action.title)}`;
    case "crm.import":
      return `Import “${action.sheetName}” → CRM: ${action.preview.created} new · ${action.preview.updated} updated · ${action.preview.held} held (${action.preview.rows} rows)`;
    case "crm.ingest_review":
      return `Review ${action.held} low-confidence record(s) extracted from “${action.sheetName}” — approve to write them to the CRM`;
    case "calendar.schedule":
      return `Schedule ${action.eventKind} “${truncate(action.title, 80)}”${action.attendees?.length ? ` with ${action.attendees.length} attendee(s)` : ""} — notifies + emails attendees`;
    case "calendar.cancel":
      return `Cancel calendar event (id ${action.eventId.slice(0, 8)}…) — notifies attendees`;
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
        summary = describeAction(JSON.parse(decryptField(workspaceId, r.payloadEnc)) as AgentAction);
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
  decidedByRole: Role,
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
  // CM2-B-B004 / CIT-COMMS-002: re-check the APPROVER's role against the capability
  // the action's direct path requires, and forbid self-approval of high-risk actions.
  // The approval queue must never be a lower-privileged path to a privileged op.
  const authzErr = approvalAuthzError(decidedByRole, action, decidedBy, appr.requestedBySub);
  if (authzErr) throw new GuardError(403, authzErr);

  // CM2-B-B012: atomically claim the approval (compare-and-swap on status) BEFORE
  // executing, so two concurrent approvals of the same id cannot both run the
  // action. The prior read-check-execute-write sequence let both requests pass the
  // `status !== "pending"` check before either wrote, double-executing `runner.*`,
  // `crm.delete`, etc. The UPDATE is predicated on status='pending' and returns the
  // row only to the winner.
  const claimed = await db()
    .update(agentApprovals)
    .set({ status: "executing" })
    .where(
      and(
        eq(agentApprovals.workspaceId, workspaceId),
        eq(agentApprovals.id, approvalId),
        eq(agentApprovals.status, "pending"),
      ),
    )
    .returning({ id: agentApprovals.id });
  if (claimed.length === 0) return { ok: false, error: "already_decided" };

  let result: unknown;
  try {
    result = await executeAction(workspaceId, action, { bySub: appr.requestedBySub, personaId: appr.personaId });
  } catch {
    // Execution failed (e.g. runner unreachable) — release the claim back to pending
    // so it can be retried by a fresh decision.
    await db()
      .update(agentApprovals)
      .set({ status: "pending" })
      .where(and(eq(agentApprovals.id, approvalId), eq(agentApprovals.status, "executing")));
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
    case "crm.create": {
      // Dedupe-safe: find-or-create so an agent re-run (or a near-duplicate) reuses the
      // existing record instead of piling up doubles. Then apply any custom fields.
      let recordId: string;
      let created = true;
      if (action.entity === "account") {
        const r = await upsertAccount(workspaceId, action.standard.name, action.standard.domain ?? null, by.bySub);
        recordId = r.row.id;
        created = r.created;
      } else if (action.entity === "deal") {
        if (!action.accountId) throw new Error("deal requires accountId (its parent account)");
        const r = await upsertDeal({ workspaceId, accountId: action.accountId, name: action.standard.name, valueMinor: action.standard.valueMinor ?? 0, ownerSub: by.bySub });
        recordId = r.row.id;
        created = r.created;
      } else {
        const r = await upsertContact({ workspaceId, name: action.standard.name, title: action.standard.title ?? null, accountId: action.accountId ?? null, ownerSub: by.bySub, email: null });
        recordId = r.id;
        created = r.created;
      }
      if (action.fields?.length) {
        const defs = await listFieldDefs(workspaceId, action.entity, { includeDisabled: true });
        for (const f of action.fields) {
          const def = defs.find((d) => d.key === f.key);
          if (def) await setFieldValue({ workspaceId, entity: action.entity, recordId, fieldId: def.id, raw: f.value, bySub: by.bySub, byAgent: true });
        }
      }
      await recordActivity({ workspaceId, entity: action.entity, recordId, actorSub: by.bySub, byAgent: true, input: { kind: "agent_action", tool: "crm.create" } });
      return { created, recordId, deduped: !created };
    }
    case "crm.delete": {
      if (action.entity === "account") await deleteAccount(workspaceId, action.recordId, by.bySub);
      else if (action.entity === "deal") await deleteDeal(workspaceId, action.recordId, by.bySub);
      else await deleteContact(workspaceId, action.recordId, by.bySub);
      return { deleted: true, entity: action.entity, recordId: action.recordId };
    }
    case "crm.dedupe": {
      const report = await dedupeWorkspaceCrm(workspaceId, { actorSub: by.bySub });
      return { deduped: true, report };
    }
    case "calendar.schedule": {
      const { id } = await createEvent({
        workspaceId,
        createdBySub: by.bySub,
        kind: action.eventKind,
        title: action.title,
        startsAt: action.startsAt,
        endsAt: action.endsAt,
        timezone: action.timezone,
        location: action.location ?? null,
        description: action.description ?? null,
        channelId: action.channelId ?? null,
        attendees: action.attendees ?? [],
      });
      return { scheduled: true, eventId: id };
    }
    case "calendar.cancel": {
      await cancelEvent(workspaceId, action.eventId, by.bySub);
      return { cancelled: true, eventId: action.eventId };
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
      const task = await createTask({
        workspaceId,
        projectId: action.projectId ?? null,
        title: action.title,
        priority: action.priority ?? null,
        assigneeSub: action.assigneeSub ?? null,
        due: action.due ? new Date(action.due) : null,
        actorSub: by.bySub,
      });
      if (action.raci?.length) await setTaskRaci(workspaceId, task.id, action.raci, by.bySub);
      return { taskId: task.id };
    }
    case "crm.import": {
      // Approving the import approves its mapping, creates the job, and runs the FIRST
      // slice now. The remaining slices continue via the job tick (progress UI + cron),
      // so this stays within the request budget even for thousands of rows.
      await approveMapping(workspaceId, action.mappingId);
      const jobId = await createImportJob({ workspaceId, sheetId: action.sheetId, mappingId: action.mappingId, bySub: by.bySub });
      const progress = await runImportSlice(workspaceId, jobId);
      return { jobId, progress };
    }
    case "crm.ingest_review": {
      // A human approved the held low-confidence records — flush them to the CRM.
      const flush = await flushHeldRows(workspaceId, action.jobId);
      return { jobId: action.jobId, ...flush };
    }
  }
}
