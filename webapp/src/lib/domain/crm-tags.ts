/**
 * CRM tags (COMMS-CRM-DEPTH §3) — categorical labels for cross-record filtering.
 * Tags are controlled labels (not free-text PII), so they're stored cleartext for
 * display + filtering.
 */
import { and, asc, eq, inArray } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmTags, crmRecordTags, accounts, deals, contacts } from "@/lib/db/schema";
import { GuardError } from "@/lib/tenant/guard";
import { recordActivity } from "./crm-activity";
import type { CrmEntity } from "./crm-enums";

export interface TagRow {
  id: string;
  label: string;
  color: string | null;
}

export async function listTags(workspaceId: string): Promise<TagRow[]> {
  return db()
    .select({ id: crmTags.id, label: crmTags.label, color: crmTags.color })
    .from(crmTags)
    .where(eq(crmTags.workspaceId, workspaceId))
    .orderBy(asc(crmTags.label));
}

export async function createTag(workspaceId: string, label: string, color?: string | null): Promise<TagRow> {
  const [row] = await db()
    .insert(crmTags)
    .values({ workspaceId, label: label.trim(), color: color ?? null })
    .onConflictDoNothing()
    .returning({ id: crmTags.id, label: crmTags.label, color: crmTags.color });
  if (row) return row;
  // Already existed — return it.
  const [existing] = await db()
    .select({ id: crmTags.id, label: crmTags.label, color: crmTags.color })
    .from(crmTags)
    .where(and(eq(crmTags.workspaceId, workspaceId), eq(crmTags.label, label.trim())))
    .limit(1);
  return existing!;
}

export async function tagsForRecord(workspaceId: string, entity: CrmEntity, recordId: string): Promise<TagRow[]> {
  const rows = await db()
    .select({ id: crmTags.id, label: crmTags.label, color: crmTags.color })
    .from(crmRecordTags)
    .innerJoin(crmTags, eq(crmRecordTags.tagId, crmTags.id))
    .where(and(eq(crmRecordTags.workspaceId, workspaceId), eq(crmRecordTags.entity, entity), eq(crmRecordTags.recordId, recordId)))
    .orderBy(asc(crmTags.label));
  return rows;
}

/** Throw unless `tagId` is a tag of `workspaceId` (PBA-L3c-027). */
async function assertTagInWorkspace(workspaceId: string, tagId: string): Promise<string> {
  const [tag] = await db()
    .select({ label: crmTags.label })
    .from(crmTags)
    .where(and(eq(crmTags.workspaceId, workspaceId), eq(crmTags.id, tagId)))
    .limit(1);
  if (!tag) throw new GuardError(403, "tag not in this workspace");
  return tag.label;
}

/** The subset of `ids` that are records of `entity` in `workspaceId` (PBA-L3c-027). */
async function existingRecordIds(workspaceId: string, entity: CrmEntity, ids: string[]): Promise<string[]> {
  if (ids.length === 0) return [];
  const t = entity === "account" ? accounts : entity === "deal" ? deals : contacts;
  const rows = await db()
    .select({ id: t.id })
    .from(t)
    .where(and(eq(t.workspaceId, workspaceId), inArray(t.id, ids)));
  const found = new Set(rows.map((r) => r.id));
  return ids.filter((i) => found.has(i));
}

export async function tagRecord(args: {
  workspaceId: string;
  entity: CrmEntity;
  recordId: string;
  tagId: string;
  actorSub: string;
}): Promise<void> {
  // PBA-L3c-027: never persist a link to another workspace's tag or a non-existent record.
  const label = await assertTagInWorkspace(args.workspaceId, args.tagId);
  if ((await existingRecordIds(args.workspaceId, args.entity, [args.recordId])).length === 0) throw new GuardError(403, "record not in this workspace");
  await db()
    .insert(crmRecordTags)
    .values({ workspaceId: args.workspaceId, entity: args.entity, recordId: args.recordId, tagId: args.tagId })
    .onConflictDoNothing();
  await recordActivity({
    workspaceId: args.workspaceId,
    entity: args.entity,
    recordId: args.recordId,
    actorSub: args.actorSub,
    input: { kind: "tagged", tag: label },
    meta: { tagId: args.tagId },
  });
}

/** Apply one tag to many records at once (D4 bulk action). */
export async function bulkTagRecords(args: {
  workspaceId: string;
  entity: CrmEntity;
  recordIds: string[];
  tagId: string;
  actorSub: string;
}): Promise<number> {
  if (args.recordIds.length === 0) return 0;
  // PBA-L3c-027: the tag must be this workspace's, and only real records get tagged.
  const label = await assertTagInWorkspace(args.workspaceId, args.tagId);
  const recordIds = await existingRecordIds(args.workspaceId, args.entity, args.recordIds);
  if (recordIds.length === 0) return 0;
  await db()
    .insert(crmRecordTags)
    .values(recordIds.map((recordId) => ({ workspaceId: args.workspaceId, entity: args.entity, recordId, tagId: args.tagId })))
    .onConflictDoNothing();
  const tag = { label };
  for (const recordId of recordIds) {
    await recordActivity({
      workspaceId: args.workspaceId,
      entity: args.entity,
      recordId,
      actorSub: args.actorSub,
      input: { kind: "tagged", tag: tag?.label ?? "tag" },
      meta: { tagId: args.tagId },
    });
  }
  return recordIds.length;
}

export async function untagRecord(workspaceId: string, entity: CrmEntity, recordId: string, tagId: string): Promise<void> {
  await db()
    .delete(crmRecordTags)
    .where(
      and(
        eq(crmRecordTags.workspaceId, workspaceId),
        eq(crmRecordTags.entity, entity),
        eq(crmRecordTags.recordId, recordId),
        eq(crmRecordTags.tagId, tagId),
      ),
    );
}
