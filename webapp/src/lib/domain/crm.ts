/**
 * CRM repository — accounts, contacts, and deals. Deals are CHILDREN of an account
 * (the locked decision: add-customer → add-deal-under-customer). The pipeline is a
 * kanban by stage. All workspace-scoped; mutations audited at the API layer.
 */
import { and, asc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { accounts, contacts, deals } from "@/lib/db/schema";
import { DEAL_STAGES, type DealStage } from "./enums";

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
  return row!;
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

/** Move a deal to a new pipeline stage. */
export async function moveDealStage(workspaceId: string, dealId: string, stage: DealStage): Promise<void> {
  await db()
    .update(deals)
    .set({ stage })
    .where(and(eq(deals.workspaceId, workspaceId), eq(deals.id, dealId)));
}

export interface ContactRow {
  id: string;
  name: string;
  title: string | null;
  accountId: string | null;
  ownerSub: string | null;
}

export async function listContacts(workspaceId: string): Promise<ContactRow[]> {
  const rows = await db()
    .select({ id: contacts.id, name: contacts.name, title: contacts.title, accountId: contacts.accountId, ownerSub: contacts.ownerSub })
    .from(contacts)
    .where(eq(contacts.workspaceId, workspaceId))
    .orderBy(asc(contacts.name));
  return rows;
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
  return row!;
}
