/**
 * CRM record-file aggregator (COMMS-CRM-DEPTH §2, L1). Assembles everything the record
 * detail page shows: standard header stats + custom field values + tags + notes/journal
 * + activity feed + related records + documents + trust-tiered memories. Server-only.
 */
import { getAccount, getDeal, getContact, listDealsForAccount, listContactsForAccount } from "./crm";
import { getFieldsForRecord, type FieldWithValue } from "./crm-fields";
import { listNotes, type NoteRow } from "./crm-notes";
import { listActivity, type ActivityRow } from "./crm-activity";
import { tagsForRecord, type TagRow } from "./crm-tags";
import { listDocumentsForRecord, type DocumentRow } from "./documents";
import { getMemoryStore, crmRepo } from "@/lib/memory";
import type { CrmEntity } from "./crm-enums";

export interface RelatedItem {
  id: string;
  name: string;
  entity: CrmEntity;
  meta?: string;
}
export interface RelatedGroup {
  label: string;
  items: RelatedItem[];
}
export interface MemoryCitation {
  content: string;
  trustTier: string;
  confidence: number;
}

export interface RecordFile {
  entity: CrmEntity;
  recordId: string;
  title: string;
  subtitle: string | null;
  headerStats: { label: string; value: string }[];
  fields: FieldWithValue[];
  tags: TagRow[];
  notes: NoteRow[];
  activity: ActivityRow[];
  related: RelatedGroup[];
  documents: DocumentRow[];
  memories: MemoryCitation[];
}

function money(minor: number): string {
  return `$${(minor / 100).toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
}

async function recallMemories(workspaceId: string, entity: CrmEntity, id: string, query: string): Promise<MemoryCitation[]> {
  try {
    const store = await getMemoryStore();
    const res = await store.recall(crmRepo(workspaceId), { query, anchors: [{ entity, id }], budget: 8 });
    return res.items.map((m) => ({ content: m.content, trustTier: m.trustTier, confidence: m.confidence }));
  } catch {
    return [];
  }
}

export async function getAccountFile(workspaceId: string, id: string): Promise<RecordFile | null> {
  const account = await getAccount(workspaceId, id);
  if (!account) return null;
  const [fields, tags, notes, activity, deals, contacts, documents, memories] = await Promise.all([
    getFieldsForRecord(workspaceId, "account", id),
    tagsForRecord(workspaceId, "account", id),
    listNotes(workspaceId, "account", id),
    listActivity(workspaceId, "account", id),
    listDealsForAccount(workspaceId, id),
    listContactsForAccount(workspaceId, id),
    listDocumentsForRecord(workspaceId, { accountId: id }),
    recallMemories(workspaceId, "account", id, account.name),
  ]);
  return {
    entity: "account",
    recordId: id,
    title: account.name,
    subtitle: account.domain,
    headerStats: [
      { label: "Domain", value: account.domain ?? "—" },
      { label: "Open deals", value: String(deals.filter((d) => d.stage !== "Won" && d.stage !== "Lost").length) },
      { label: "Pipeline", value: money(deals.filter((d) => d.stage !== "Lost").reduce((s, d) => s + d.valueMinor, 0)) },
    ],
    fields,
    tags,
    notes,
    activity,
    related: [
      { label: "Deals", items: deals.map((d) => ({ id: d.id, name: d.name, entity: "deal", meta: `${d.stage} · ${money(d.valueMinor)}` })) },
      { label: "Contacts", items: contacts.map((c) => ({ id: c.id, name: c.name, entity: "contact", meta: c.title ?? undefined })) },
    ],
    documents,
    memories,
  };
}

export async function getDealFile(workspaceId: string, id: string): Promise<RecordFile | null> {
  const deal = await getDeal(workspaceId, id);
  if (!deal) return null;
  const [fields, tags, notes, activity, documents, memories] = await Promise.all([
    getFieldsForRecord(workspaceId, "deal", id),
    tagsForRecord(workspaceId, "deal", id),
    listNotes(workspaceId, "deal", id),
    listActivity(workspaceId, "deal", id),
    listDocumentsForRecord(workspaceId, { dealId: id }),
    recallMemories(workspaceId, "deal", id, deal.name),
  ]);
  return {
    entity: "deal",
    recordId: id,
    title: deal.name,
    subtitle: deal.accountName,
    headerStats: [
      { label: "Stage", value: deal.stage },
      { label: "Value", value: money(deal.valueMinor) },
      { label: "Account", value: deal.accountName ?? "—" },
    ],
    fields,
    tags,
    notes,
    activity,
    related: deal.accountId
      ? [{ label: "Account", items: [{ id: deal.accountId, name: deal.accountName ?? "Account", entity: "account" }] }]
      : [],
    documents,
    memories,
  };
}

export async function getContactFile(workspaceId: string, id: string): Promise<RecordFile | null> {
  const contact = await getContact(workspaceId, id);
  if (!contact) return null;
  const [fields, tags, notes, activity, memories] = await Promise.all([
    getFieldsForRecord(workspaceId, "contact", id),
    tagsForRecord(workspaceId, "contact", id),
    listNotes(workspaceId, "contact", id),
    listActivity(workspaceId, "contact", id),
    recallMemories(workspaceId, "contact", id, contact.name),
  ]);
  return {
    entity: "contact",
    recordId: id,
    title: contact.name,
    subtitle: contact.title,
    headerStats: [
      { label: "Title", value: contact.title ?? "—" },
      { label: "Account", value: contact.accountName ?? "—" },
    ],
    fields,
    tags,
    notes,
    activity,
    related: contact.accountId
      ? [{ label: "Account", items: [{ id: contact.accountId, name: contact.accountName ?? "Account", entity: "account" }] }]
      : [],
    documents: [],
    memories,
  };
}
