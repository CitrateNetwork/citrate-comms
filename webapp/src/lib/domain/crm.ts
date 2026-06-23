/**
 * CRM repository — accounts, contacts, and deals. Deals are CHILDREN of an account
 * (the locked decision: add-customer → add-deal-under-customer). The pipeline is a
 * kanban by stage. All workspace-scoped; mutations audited at the API layer.
 */
import { and, eq, inArray, asc } from "drizzle-orm";
import { db } from "@/lib/db/client";
import {
  accounts,
  contacts,
  deals,
  agentThreads,
  documents,
  crmFieldValues,
  crmNotes,
  crmNoteComments,
  crmActivity,
  crmRecordTags,
} from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";
import { DEAL_STAGES, type DealStage } from "./enums";
import { recordActivity } from "./crm-activity";
import type { CrmEntity } from "./crm-enums";

export { DEAL_STAGES };
export type { DealStage };

export interface AccountRow {
  id: string;
  name: string;
  domain: string | null;
  ownerSub: string | null;
}
export interface DealRow {
  id: string;
  accountId: string | null;
  accountName: string | null;
  name: string;
  valueMinor: number;
  stage: DealStage;
  ownerSub: string | null;
  linkedChannelId: string | null;
}

export async function listAccounts(workspaceId: string): Promise<AccountRow[]> {
  const rows = await db()
    .select({ id: accounts.id, name: accounts.name, domain: accounts.domain, ownerSub: accounts.ownerSub })
    .from(accounts)
    .where(eq(accounts.workspaceId, workspaceId))
    .orderBy(asc(accounts.name));
  return rows;
}

export async function createAccount(workspaceId: string, name: string, domain: string | null, ownerSub: string): Promise<AccountRow> {
  const [row] = await db()
    .insert(accounts)
    .values({ workspaceId, name: name.trim(), domain: domain?.trim() || null, ownerSub })
    .returning({ id: accounts.id, name: accounts.name, domain: accounts.domain, ownerSub: accounts.ownerSub });
  await recordActivity({ workspaceId, entity: "account", recordId: row!.id, actorSub: ownerSub, input: { kind: "created" } });
  return row!;
}

/** Confirm a record exists within the workspace (tenant-safety before sub-writes). */
export async function recordExists(workspaceId: string, entity: "account" | "deal" | "contact", id: string): Promise<boolean> {
  if (entity === "account") return (await getAccount(workspaceId, id)) !== null;
  if (entity === "deal") return (await getDeal(workspaceId, id)) !== null;
  return (await getContact(workspaceId, id)) !== null;
}

/** Update an account's standard fields (records value-free activity per changed field). */
export async function updateAccount(
  workspaceId: string,
  id: string,
  patch: { name?: string; domain?: string | null },
  actorSub: string,
): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.name !== undefined) set.name = patch.name.trim();
  if (patch.domain !== undefined) set.domain = patch.domain?.trim() || null;
  if (Object.keys(set).length === 0) return;
  await db().update(accounts).set(set).where(and(eq(accounts.workspaceId, workspaceId), eq(accounts.id, id)));
  for (const label of fieldLabels(patch, { name: "Name", domain: "Domain" })) {
    await recordActivity({ workspaceId, entity: "account", recordId: id, actorSub, input: { kind: "field_changed", fieldLabel: label } });
  }
}

/** Update a deal's standard fields. */
export async function updateDeal(
  workspaceId: string,
  id: string,
  patch: { name?: string; valueMinor?: number },
  actorSub: string,
): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.name !== undefined) set.name = patch.name.trim();
  if (patch.valueMinor !== undefined) set.valueMinor = patch.valueMinor;
  if (Object.keys(set).length === 0) return;
  await db().update(deals).set(set).where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, id)));
  for (const label of fieldLabels(patch, { name: "Name", valueMinor: "Value" })) {
    await recordActivity({ workspaceId, entity: "deal", recordId: id, actorSub, input: { kind: "field_changed", fieldLabel: label } });
  }
}

/** Update a contact's standard fields. */
export async function updateContact(
  workspaceId: string,
  id: string,
  patch: { name?: string; title?: string | null },
  actorSub: string,
): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.name !== undefined) set.name = patch.name.trim();
  if (patch.title !== undefined) set.title = patch.title?.trim() || null;
  if (Object.keys(set).length === 0) return;
  await db().update(contacts).set(set).where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.id, id)));
  for (const label of fieldLabels(patch, { name: "Name", title: "Title" })) {
    await recordActivity({ workspaceId, entity: "contact", recordId: id, actorSub, input: { kind: "field_changed", fieldLabel: label } });
  }
}

/** Map the keys present in a patch to their human labels (for value-free activity). */
function fieldLabels<T extends object>(patch: T, labels: Partial<Record<keyof T, string>>): string[] {
  return (Object.keys(patch) as (keyof T)[]).filter((k) => patch[k] !== undefined && labels[k]).map((k) => labels[k]!);
}

/** A single account in a workspace, or null. */
export async function getAccount(workspaceId: string, id: string): Promise<AccountRow | null> {
  const [row] = await db()
    .select({ id: accounts.id, name: accounts.name, domain: accounts.domain, ownerSub: accounts.ownerSub })
    .from(accounts)
    .where(and(eq(accounts.workspaceId, workspaceId), eq(accounts.id, id)))
    .limit(1);
  return row ?? null;
}

export async function listDeals(workspaceId: string): Promise<DealRow[]> {
  const rows = await db()
    .select({
      id: deals.id,
      accountId: deals.accountId,
      accountName: accounts.name,
      name: deals.name,
      valueMinor: deals.valueMinor,
      stage: deals.stage,
      ownerSub: deals.ownerSub,
      linkedChannelId: deals.linkedChannelId,
    })
    .from(deals)
    .leftJoin(accounts, eq(deals.accountId, accounts.id))
    .where(eq(deals.workspaceId, workspaceId))
    .orderBy(asc(deals.createdAt));
  return rows.map((r) => ({ ...r, stage: r.stage as DealStage }));
}

export async function createDeal(args: {
  workspaceId: string;
  accountId: string;
  name: string;
  valueMinor: number;
  ownerSub: string;
}): Promise<DealRow> {
  const [row] = await db()
    .insert(deals)
    .values({
      workspaceId: args.workspaceId,
      accountId: args.accountId,
      name: args.name.trim(),
      valueMinor: args.valueMinor,
      stage: "Lead",
      ownerSub: args.ownerSub,
    })
    .returning();
  const [acct] = await db().select({ name: accounts.name }).from(accounts).where(eq(accounts.id, args.accountId)).limit(1);
  await recordActivity({ workspaceId: args.workspaceId, entity: "deal", recordId: row!.id, actorSub: args.ownerSub, input: { kind: "created" } });
  return {
    id: row!.id,
    accountId: row!.accountId,
    accountName: acct?.name ?? null,
    name: row!.name,
    valueMinor: row!.valueMinor,
    stage: row!.stage as DealStage,
    ownerSub: row!.ownerSub,
    linkedChannelId: row!.linkedChannelId,
  };
}

/** A single deal (with its account name), or null. */
export async function getDeal(workspaceId: string, id: string): Promise<DealRow | null> {
  const [row] = await db()
    .select({
      id: deals.id,
      accountId: deals.accountId,
      accountName: accounts.name,
      name: deals.name,
      valueMinor: deals.valueMinor,
      stage: deals.stage,
      ownerSub: deals.ownerSub,
      linkedChannelId: deals.linkedChannelId,
    })
    .from(deals)
    .leftJoin(accounts, eq(deals.accountId, accounts.id))
    .where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, id)))
    .limit(1);
  return row ? { ...row, stage: row.stage as DealStage } : null;
}

/** Deals under a given account. */
export async function listDealsForAccount(workspaceId: string, accountId: string): Promise<DealRow[]> {
  const rows = await db()
    .select({
      id: deals.id,
      accountId: deals.accountId,
      accountName: accounts.name,
      name: deals.name,
      valueMinor: deals.valueMinor,
      stage: deals.stage,
      ownerSub: deals.ownerSub,
      linkedChannelId: deals.linkedChannelId,
    })
    .from(deals)
    .leftJoin(accounts, eq(deals.accountId, accounts.id))
    .where(and(eq(deals.workspaceId, workspaceId), eq(deals.accountId, accountId)))
    .orderBy(asc(deals.createdAt));
  return rows.map((r) => ({ ...r, stage: r.stage as DealStage }));
}

/** Move a deal to a new pipeline stage (records a value-free activity entry). */
export async function moveDealStage(workspaceId: string, dealId: string, stage: DealStage, actorSub?: string): Promise<void> {
  const [prev] = await db()
    .select({ stage: deals.stage })
    .from(deals)
    .where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, dealId)))
    .limit(1);
  await db()
    .update(deals)
    .set({ stage })
    .where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, dealId)));
  if (prev && prev.stage !== stage) {
    await recordActivity({
      workspaceId,
      entity: "deal",
      recordId: dealId,
      actorSub: actorSub ?? null,
      input: { kind: "stage_changed", from: prev.stage, to: stage },
    });
  }
}

export interface ContactRow {
  id: string;
  name: string;
  title: string | null;
  accountId: string | null;
  accountName?: string | null;
  ownerSub: string | null;
}

export async function listContacts(workspaceId: string): Promise<ContactRow[]> {
  const rows = await db()
    .select({
      id: contacts.id,
      name: contacts.name,
      title: contacts.title,
      accountId: contacts.accountId,
      accountName: accounts.name,
      ownerSub: contacts.ownerSub,
    })
    .from(contacts)
    .leftJoin(accounts, eq(contacts.accountId, accounts.id))
    .where(eq(contacts.workspaceId, workspaceId))
    .orderBy(asc(contacts.name));
  return rows;
}

/** A single contact (with its account name), or null. */
export async function getContact(workspaceId: string, id: string): Promise<ContactRow | null> {
  const [row] = await db()
    .select({
      id: contacts.id,
      name: contacts.name,
      title: contacts.title,
      accountId: contacts.accountId,
      accountName: accounts.name,
      ownerSub: contacts.ownerSub,
    })
    .from(contacts)
    .leftJoin(accounts, eq(contacts.accountId, accounts.id))
    .where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.id, id)))
    .limit(1);
  return row ?? null;
}

/** Contacts under a given account. */
export async function listContactsForAccount(workspaceId: string, accountId: string): Promise<ContactRow[]> {
  return db()
    .select({ id: contacts.id, name: contacts.name, title: contacts.title, accountId: contacts.accountId, ownerSub: contacts.ownerSub })
    .from(contacts)
    .where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.accountId, accountId)))
    .orderBy(asc(contacts.name));
}

export async function createContact(args: {
  workspaceId: string;
  name: string;
  title: string | null;
  accountId: string | null;
  ownerSub: string;
}): Promise<ContactRow> {
  const [row] = await db()
    .insert(contacts)
    .values({
      workspaceId: args.workspaceId,
      name: args.name.trim(),
      title: args.title?.trim() || null,
      accountId: args.accountId,
      ownerSub: args.ownerSub,
    })
    .returning({ id: contacts.id, name: contacts.name, title: contacts.title, accountId: contacts.accountId, ownerSub: contacts.ownerSub });
  await recordActivity({ workspaceId: args.workspaceId, entity: "contact", recordId: row!.id, actorSub: args.ownerSub, input: { kind: "created" } });
  return row!;
}

// ── Deletes (Owner/Admin only — auditability; CRM-depth sub-data cleaned up) ──

/** Remove a record's CRM-depth sub-data (field values, notes + comments, activity, tags). */
async function deleteCrmSubData(workspaceId: string, entity: CrmEntity, recordId: string): Promise<void> {
  const d = db();
  const noteRows = await d
    .select({ id: crmNotes.id })
    .from(crmNotes)
    .where(and(eq(crmNotes.workspaceId, workspaceId), eq(crmNotes.entity, entity), eq(crmNotes.recordId, recordId)));
  const noteIds = noteRows.map((n) => n.id);
  if (noteIds.length > 0) await d.delete(crmNoteComments).where(inArray(crmNoteComments.noteId, noteIds));
  await d.delete(crmNotes).where(and(eq(crmNotes.workspaceId, workspaceId), eq(crmNotes.entity, entity), eq(crmNotes.recordId, recordId)));
  await d.delete(crmFieldValues).where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.entity, entity), eq(crmFieldValues.recordId, recordId)));
  await d.delete(crmActivity).where(and(eq(crmActivity.workspaceId, workspaceId), eq(crmActivity.entity, entity), eq(crmActivity.recordId, recordId)));
  await d.delete(crmRecordTags).where(and(eq(crmRecordTags.workspaceId, workspaceId), eq(crmRecordTags.entity, entity), eq(crmRecordTags.recordId, recordId)));
}

export async function deleteContact(workspaceId: string, id: string, actorSub: string): Promise<void> {
  await deleteCrmSubData(workspaceId, "contact", id);
  await db().delete(contacts).where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.id, id)));
  await appendAudit({ workspaceId, actorSub, event: "contact_deleted", target: id });
}

export async function deleteDeal(workspaceId: string, id: string, actorSub: string): Promise<void> {
  const d = db();
  // Unlink FK references so the survivor rows (threads, documents) aren't orphaned-deleted.
  await d.update(agentThreads).set({ dealId: null }).where(and(eq(agentThreads.workspaceId, workspaceId), eq(agentThreads.dealId, id)));
  await d.update(documents).set({ dealId: null }).where(and(eq(documents.workspaceId, workspaceId), eq(documents.dealId, id)));
  await deleteCrmSubData(workspaceId, "deal", id);
  await d.delete(deals).where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, id)));
  await appendAudit({ workspaceId, actorSub, event: "deal_deleted", target: id });
}

/** Whether an account still has child deals or contacts (blocks deletion). */
export async function accountHasChildren(workspaceId: string, id: string): Promise<boolean> {
  const [deal] = await db().select({ id: deals.id }).from(deals).where(and(eq(deals.workspaceId, workspaceId), eq(deals.accountId, id))).limit(1);
  if (deal) return true;
  const [contact] = await db().select({ id: contacts.id }).from(contacts).where(and(eq(contacts.workspaceId, workspaceId), eq(contacts.accountId, id))).limit(1);
  return Boolean(contact);
}

export async function deleteAccount(workspaceId: string, id: string, actorSub: string): Promise<void> {
  const d = db();
  await d.update(agentThreads).set({ accountId: null }).where(and(eq(agentThreads.workspaceId, workspaceId), eq(agentThreads.accountId, id)));
  await d.update(documents).set({ accountId: null }).where(and(eq(documents.workspaceId, workspaceId), eq(documents.accountId, id)));
  await deleteCrmSubData(workspaceId, "account", id);
  await d.delete(accounts).where(and(eq(accounts.workspaceId, workspaceId), eq(accounts.id, id)));
  await appendAudit({ workspaceId, actorSub, event: "account_deleted", target: id });
}
