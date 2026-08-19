/**
 * CRM de-duplication (CLEAN-1). Merges duplicate accounts/deals/contacts into a single
 * canonical record, re-pointing EVERY child/reference first (all FKs are ON DELETE no
 * action, so nothing is auto-handled), then deleting the duplicate.
 *
 * Matching (conservative — see crmNormName):
 *   - accounts: same domain OR same normalized name (transitive within a group)
 *   - deals:    same account + normalized name
 *   - contacts: same email blind-index OR same normalized name + account
 * Canonical = the earliest-created row in a group; all other rows' children are unioned
 * onto it. Unique-constrained children (crm_field_values, crm_record_tags, message_links)
 * are conflict-handled: a duplicate child that would collide with one the canonical
 * already has is dropped, keeping the canonical's.
 *
 * Used by: the one-shot cleanup script, the admin dedupe endpoint, and the crm.dedupe
 * agent tool. `dryRun` reports what WOULD merge without writing.
 */
import { and, asc, eq, inArray } from "drizzle-orm";
import { db } from "@/lib/db/client";
import {
  accounts,
  deals,
  contacts,
  documents,
  agentThreads,
  importRows,
  crmNotes,
  crmActivity,
  crmFieldValues,
  crmRecordTags,
  messageLinks,
  calendarEvents,
} from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";
import { crmNormName } from "./crm";

export type CrmEntity = "account" | "deal" | "contact";

export interface DedupeReport {
  accounts: { groups: number; merged: number };
  deals: { groups: number; merged: number };
  contacts: { groups: number; merged: number };
  dryRun: boolean;
}

/** Re-point a polymorphic child (crm_notes / crm_activity) by recordId — no unique
 *  constraint, plain update. */
async function repointPoly(table: typeof crmNotes | typeof crmActivity, workspaceId: string, entity: CrmEntity, dupId: string, canonId: string): Promise<void> {
  await db()
    .update(table)
    .set({ recordId: canonId })
    .where(and(eq(table.workspaceId, workspaceId), eq(table.entity, entity), eq(table.recordId, dupId)));
}

/** Re-point crm_field_values, dropping any duplicate whose fieldId the canonical already
 *  has (unique on workspace+record+field). */
async function repointFieldValues(workspaceId: string, entity: CrmEntity, dupId: string, canonId: string): Promise<void> {
  const canon = await db()
    .select({ fieldId: crmFieldValues.fieldId })
    .from(crmFieldValues)
    .where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.entity, entity), eq(crmFieldValues.recordId, canonId)));
  const have = new Set(canon.map((c) => c.fieldId));
  const dup = await db()
    .select({ fieldId: crmFieldValues.fieldId })
    .from(crmFieldValues)
    .where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.entity, entity), eq(crmFieldValues.recordId, dupId)));
  const collide = dup.filter((d) => have.has(d.fieldId)).map((d) => d.fieldId);
  if (collide.length) {
    await db()
      .delete(crmFieldValues)
      .where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.entity, entity), eq(crmFieldValues.recordId, dupId), inArray(crmFieldValues.fieldId, collide)));
  }
  await db()
    .update(crmFieldValues)
    .set({ recordId: canonId })
    .where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.entity, entity), eq(crmFieldValues.recordId, dupId)));
}

/** Re-point crm_record_tags, dropping duplicates whose tagId the canonical already has
 *  (PK entity+record+tag). */
async function repointTags(workspaceId: string, entity: CrmEntity, dupId: string, canonId: string): Promise<void> {
  const canon = await db()
    .select({ tagId: crmRecordTags.tagId })
    .from(crmRecordTags)
    .where(and(eq(crmRecordTags.workspaceId, workspaceId), eq(crmRecordTags.entity, entity), eq(crmRecordTags.recordId, canonId)));
  const have = new Set(canon.map((c) => c.tagId));
  const dup = await db()
    .select({ tagId: crmRecordTags.tagId })
    .from(crmRecordTags)
    .where(and(eq(crmRecordTags.workspaceId, workspaceId), eq(crmRecordTags.entity, entity), eq(crmRecordTags.recordId, dupId)));
  const collide = dup.filter((d) => have.has(d.tagId)).map((d) => d.tagId);
  if (collide.length) {
    await db()
      .delete(crmRecordTags)
      .where(and(eq(crmRecordTags.workspaceId, workspaceId), eq(crmRecordTags.entity, entity), eq(crmRecordTags.recordId, dupId), inArray(crmRecordTags.tagId, collide)));
  }
  await db()
    .update(crmRecordTags)
    .set({ recordId: canonId })
    .where(and(eq(crmRecordTags.workspaceId, workspaceId), eq(crmRecordTags.entity, entity), eq(crmRecordTags.recordId, dupId)));
}

/**
 * Merge one duplicate record into a canonical one within a workspace, then delete the
 * duplicate. Re-points all children. Safe to call for any of the three entities.
 */
export async function mergeRecord(workspaceId: string, entity: CrmEntity, dupId: string, canonId: string, actorSub: string): Promise<void> {
  if (dupId === canonId) return;
  const d = db();

  // shared polymorphic children
  await repointPoly(crmNotes, workspaceId, entity, dupId, canonId);
  await repointPoly(crmActivity, workspaceId, entity, dupId, canonId);
  await repointFieldValues(workspaceId, entity, dupId, canonId);
  await repointTags(workspaceId, entity, dupId, canonId);

  if (entity === "account") {
    await d.update(contacts).set({ accountId: canonId }).where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.accountId, dupId)));
    await d.update(deals).set({ accountId: canonId }).where(and(eq(deals.workspaceId, workspaceId), eq(deals.accountId, dupId)));
    await d.update(documents).set({ accountId: canonId }).where(and(eq(documents.workspaceId, workspaceId), eq(documents.accountId, dupId)));
    await d.update(agentThreads).set({ accountId: canonId }).where(and(eq(agentThreads.workspaceId, workspaceId), eq(agentThreads.accountId, dupId)));
    await d.update(importRows).set({ linkedAccountId: canonId }).where(and(eq(importRows.workspaceId, workspaceId), eq(importRows.linkedAccountId, dupId)));
    await d.delete(accounts).where(and(eq(accounts.workspaceId, workspaceId), eq(accounts.id, dupId)));
  } else if (entity === "deal") {
    await d.update(documents).set({ dealId: canonId }).where(and(eq(documents.workspaceId, workspaceId), eq(documents.dealId, dupId)));
    await d.update(agentThreads).set({ dealId: canonId }).where(and(eq(agentThreads.workspaceId, workspaceId), eq(agentThreads.dealId, dupId)));
    await d.update(calendarEvents).set({ dealId: canonId }).where(and(eq(calendarEvents.workspaceId, workspaceId), eq(calendarEvents.dealId, dupId)));
    // message_links: PK (messageId, entityType, entityId) — drop dup links to messages
    // the canonical is already linked to, re-point the rest.
    const canonMsgs = await d.select({ messageId: messageLinks.messageId }).from(messageLinks).where(and(eq(messageLinks.entityType, "deal"), eq(messageLinks.entityId, canonId)));
    const have = new Set(canonMsgs.map((m) => m.messageId));
    const dupMsgs = await d.select({ messageId: messageLinks.messageId }).from(messageLinks).where(and(eq(messageLinks.entityType, "deal"), eq(messageLinks.entityId, dupId)));
    const collide = dupMsgs.filter((m) => have.has(m.messageId)).map((m) => m.messageId);
    if (collide.length) await d.delete(messageLinks).where(and(eq(messageLinks.entityType, "deal"), eq(messageLinks.entityId, dupId), inArray(messageLinks.messageId, collide)));
    await d.update(messageLinks).set({ entityId: canonId }).where(and(eq(messageLinks.entityType, "deal"), eq(messageLinks.entityId, dupId)));
    await d.delete(deals).where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, dupId)));
  } else {
    await d.update(importRows).set({ linkedContactId: canonId }).where(and(eq(importRows.workspaceId, workspaceId), eq(importRows.linkedContactId, dupId)));
    await d.delete(contacts).where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.id, dupId)));
  }

  await appendAudit({ workspaceId, actorSub, event: `${entity}_merged`, target: `${dupId}->${canonId}` });
}

/**
 * Find + merge all duplicate accounts, deals, and contacts in a workspace. Deals are
 * deduped within their account. Returns counts; `dryRun` computes without writing.
 */
export async function dedupeWorkspaceCrm(workspaceId: string, opts: { dryRun?: boolean; actorSub?: string; maxMerges?: number } = {}): Promise<DedupeReport> {
  const dryRun = opts.dryRun ?? false;
  const actor = opts.actorSub ?? "system:dedupe";
  // Per-call merge budget so a huge cleanup runs in resumable batches (each real merge is
  // several queries; thousands in one request would exceed the serverless timeout). The
  // caller loops until a run merges 0. Dry-run ignores the cap (it only counts).
  const cap = !dryRun && opts.maxMerges && opts.maxMerges > 0 ? opts.maxMerges : Infinity;
  let budget = cap;
  const report: DedupeReport = { accounts: { groups: 0, merged: 0 }, deals: { groups: 0, merged: 0 }, contacts: { groups: 0, merged: 0 }, dryRun };

  // ── accounts: canonical keyed by domain OR normalized name (transitive) ──
  const accRows = await db().select({ id: accounts.id, name: accounts.name, domain: accounts.domain, createdAt: accounts.createdAt }).from(accounts).where(eq(accounts.workspaceId, workspaceId)).orderBy(asc(accounts.createdAt));
  {
    const canonBy = new Map<string, string>(); // key → canonical id
    const groupsSeen = new Set<string>();
    for (const a of accRows) {
      if (budget <= 0) break;
      const kd = a.domain?.trim().toLowerCase() ? `d:${a.domain.trim().toLowerCase()}` : null;
      const kn = `n:${crmNormName(a.name)}`;
      const canon = (kd && canonBy.get(kd)) || canonBy.get(kn);
      if (canon) {
        groupsSeen.add(canon);
        report.accounts.merged++;
        if (!dryRun) {
          await mergeRecord(workspaceId, "account", a.id, canon, actor);
          budget--;
        }
        if (kd && !canonBy.has(kd)) canonBy.set(kd, canon);
      } else {
        if (kd) canonBy.set(kd, a.id);
        canonBy.set(kn, a.id);
      }
    }
    report.accounts.groups = groupsSeen.size;
  }

  // ── deals: within account, by normalized name ──
  const dealRows = await db().select({ id: deals.id, name: deals.name, accountId: deals.accountId, createdAt: deals.createdAt }).from(deals).where(eq(deals.workspaceId, workspaceId)).orderBy(asc(deals.createdAt));
  {
    const canonBy = new Map<string, string>();
    const groupsSeen = new Set<string>();
    for (const dl of dealRows) {
      if (budget <= 0) break;
      const key = `${dl.accountId ?? ""}|${crmNormName(dl.name)}`;
      const canon = canonBy.get(key);
      if (canon) {
        groupsSeen.add(canon);
        report.deals.merged++;
        if (!dryRun) {
          await mergeRecord(workspaceId, "deal", dl.id, canon, actor);
          budget--;
        }
      } else {
        canonBy.set(key, dl.id);
      }
    }
    report.deals.groups = groupsSeen.size;
  }

  // ── contacts: by email blind-index OR normalized name + account ──
  const ctRows = await db().select({ id: contacts.id, name: contacts.name, accountId: contacts.accountId, emailKey: contacts.emailKey }).from(contacts).where(eq(contacts.workspaceId, workspaceId));
  {
    const canonBy = new Map<string, string>();
    const groupsSeen = new Set<string>();
    for (const c of ctRows) {
      if (budget <= 0) break;
      const ke = c.emailKey ? `e:${c.emailKey}` : null;
      const kn = `n:${c.accountId ?? ""}|${crmNormName(c.name)}`;
      const canon = (ke && canonBy.get(ke)) || canonBy.get(kn);
      if (canon) {
        groupsSeen.add(canon);
        report.contacts.merged++;
        if (!dryRun) {
          await mergeRecord(workspaceId, "contact", c.id, canon, actor);
          budget--;
        }
        if (ke && !canonBy.has(ke)) canonBy.set(ke, canon);
      } else {
        if (ke) canonBy.set(ke, c.id);
        canonBy.set(kn, c.id);
      }
    }
    report.contacts.groups = groupsSeen.size;
  }

  return report;
}
