/**
 * CRM activity feed (COMMS-CRM-DEPTH §3). An automatic, append-only history per record.
 *
 * INVARIANT — summaries are VALUE-FREE. The summary is built here from a controlled
 * template over a discriminated input; call sites can never inject a raw record value
 * (a name, number, email…). Only controlled tokens flow in: deal stages (enum), field
 * LABELS (admin-defined names, not values), note types, tool names. `meta_json` carries
 * ids/hashes only. This keeps the human-facing feed safe to render unencrypted.
 *
 * Best-effort: a failed activity write never breaks the underlying mutation.
 */
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmActivity } from "@/lib/db/schema";
import type { CrmEntity } from "./crm-enums";

export type ActivityInput =
  | { kind: "created" }
  | { kind: "stage_changed"; from: string; to: string }
  | { kind: "field_changed"; fieldLabel: string }
  | { kind: "note_added"; noteType: string }
  | { kind: "document_added" }
  | { kind: "contact_linked" }
  | { kind: "tagged"; tag: string }
  | { kind: "agent_action"; tool: string };

const ENTITY_LABEL: Record<CrmEntity, string> = { account: "Account", deal: "Deal", contact: "Contact" };

/** Build a short, value-free summary from controlled tokens only. */
export function summarizeActivity(entity: CrmEntity, i: ActivityInput): string {
  switch (i.kind) {
    case "created":
      return `${ENTITY_LABEL[entity]} created`;
    case "stage_changed":
      return `Stage ${i.from}→${i.to}`;
    case "field_changed":
      return `Field “${i.fieldLabel}” updated`;
    case "note_added":
      return `${capitalize(i.noteType)} added`;
    case "document_added":
      return "Document added";
    case "contact_linked":
      return "Contact linked";
    case "tagged":
      return `Tagged “${i.tag}”`;
    case "agent_action":
      return `Agent ran ${i.tool}`;
  }
}

function capitalize(s: string): string {
  return s.length ? s[0]!.toUpperCase() + s.slice(1) : s;
}

export interface RecordActivityArgs {
  workspaceId: string;
  entity: CrmEntity;
  recordId: string;
  actorSub?: string | null;
  byAgent?: boolean;
  input: ActivityInput;
  meta?: Record<string, unknown>; // ids/hashes ONLY — never raw values
}

/** Append one activity row (best-effort — never throws). */
export async function recordActivity(args: RecordActivityArgs): Promise<void> {
  try {
    await db().insert(crmActivity).values({
      workspaceId: args.workspaceId,
      entity: args.entity,
      recordId: args.recordId,
      kind: args.input.kind,
      actorSub: args.actorSub ?? null,
      byAgent: args.byAgent ?? false,
      summary: summarizeActivity(args.entity, args.input),
      metaJson: args.meta ?? null,
    });
  } catch {
    /* activity is non-critical — never break the mutation it describes */
  }
}

export interface ActivityRow {
  id: string;
  kind: string;
  actorSub: string | null;
  byAgent: boolean;
  summary: string;
  createdAt: string;
}

export async function listActivity(
  workspaceId: string,
  entity: CrmEntity,
  recordId: string,
  limit = 50,
): Promise<ActivityRow[]> {
  const rows = await db()
    .select({
      id: crmActivity.id,
      kind: crmActivity.kind,
      actorSub: crmActivity.actorSub,
      byAgent: crmActivity.byAgent,
      summary: crmActivity.summary,
      createdAt: crmActivity.createdAt,
    })
    .from(crmActivity)
    .where(and(eq(crmActivity.workspaceId, workspaceId), eq(crmActivity.entity, entity), eq(crmActivity.recordId, recordId)))
    .orderBy(desc(crmActivity.createdAt))
    .limit(limit);
  return rows.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() }));
}
