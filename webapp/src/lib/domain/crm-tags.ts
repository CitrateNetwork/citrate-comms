/**
 * CRM tags (COMMS-CRM-DEPTH §3) — categorical labels for cross-record filtering.
 * Tags are controlled labels (not free-text PII), so they're stored cleartext for
 * display + filtering.
 */
import { and, asc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmTags, crmRecordTags } from "@/lib/db/schema";
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

export async function tagRecord(args: {
  workspaceId: string;
  entity: CrmEntity;
  recordId: string;
  tagId: string;
  actorSub: string;
}): Promise<void> {
  await db()
    .insert(crmRecordTags)
    .values({ workspaceId: args.workspaceId, entity: args.entity, recordId: args.recordId, tagId: args.tagId })
    .onConflictDoNothing();
  const [tag] = await db()
    .select({ label: crmTags.label })
    .from(crmTags)
    .where(and(eq(crmTags.workspaceId, args.workspaceId), eq(crmTags.id, args.tagId)))
    .limit(1);
  await recordActivity({
    workspaceId: args.workspaceId,
    entity: args.entity,
    recordId: args.recordId,
    actorSub: args.actorSub,
    input: { kind: "tagged", tag: tag?.label ?? "tag" },
    meta: { tagId: args.tagId },
  });
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
