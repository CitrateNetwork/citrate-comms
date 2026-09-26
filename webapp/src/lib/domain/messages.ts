/**
 * Message repository. Bodies are AES-256-GCM encrypted at rest with a per-workspace
 * key (lib/security/crypto.ts) — the honest trust boundary: the web tier CAN decrypt
 * (it holds the master key), unlike the native server-blind relay, but a raw DB dump
 * yields no plaintext. Each message gets a per-channel monotonic `seq` (the poll/SSE
 * cursor), assigned atomically inside the INSERT.
 */
import { and, asc, desc, eq, gt, inArray, ne, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { messages, messageAttachments, documents } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";

export interface MessageAttachment {
  id: string;
  name: string;
  mime: string | null;
  url: string; // access-controlled inline proxy URL ("" when there is no stored original)
}

/** Access-controlled inline-view URL for a document (the download proxy, inline mode). */
export function documentViewUrl(workspaceId: string, documentId: string): string {
  return `/api/workspaces/${workspaceId}/documents/${documentId}/download?inline=1`;
}

export interface MessageRow {
  id: string;
  channelId: string;
  authorSub: string;
  fromAgent: boolean;
  body: string;
  state: string;
  seq: number;
  threadId: string | null;
  parentId: string | null;
  onBehalfOf: string | null;
  pinned: boolean;
  attachments: MessageAttachment[];
  createdAt: string;
}

function decode(workspaceId: string, r: typeof messages.$inferSelect): MessageRow {
  return {
    id: r.id,
    channelId: r.channelId,
    authorSub: r.authorSub,
    fromAgent: r.fromAgent,
    body: safeDecrypt(workspaceId, r.bodyEnc),
    state: r.state,
    seq: r.seq,
    threadId: r.threadId,
    parentId: r.parentId,
    onBehalfOf: r.onBehalfOf,
    pinned: r.pinned,
    attachments: [],
    createdAt: r.createdAt.toISOString(),
  };
}

/** Batch-load attachments for a set of messages → messageId → [attachments]. */
async function attachmentsForMessages(workspaceId: string, messageIds: string[]): Promise<Map<string, MessageAttachment[]>> {
  const out = new Map<string, MessageAttachment[]>();
  if (messageIds.length === 0) return out;
  const rows = await db()
    .select({ messageId: messageAttachments.messageId, id: documents.id, name: documents.name, mime: documents.mime, blobUrl: documents.blobUrl })
    .from(messageAttachments)
    .innerJoin(documents, eq(messageAttachments.documentId, documents.id))
    // PBA-L3c-005: both sides of the join are pinned to the workspace.
    .where(and(eq(messageAttachments.workspaceId, workspaceId), eq(documents.workspaceId, workspaceId), inArray(messageAttachments.messageId, messageIds)));
  for (const r of rows) {
    const list = out.get(r.messageId) ?? [];
    // PBA-L3c-009 / ATT-HARDEN: never hand the raw store URL to clients — inline display
    // goes through the access-controlled proxy, which authorizes the viewer and then issues
    // a short-lived signed URL, so a removed member or non-participant can't keep or share a
    // working link.
    list.push({ id: r.id, name: r.name, mime: r.mime, url: r.blobUrl ? documentViewUrl(workspaceId, r.id) : "" });
    out.set(r.messageId, list);
  }
  return out;
}

/** Link uploaded documents to a message (idempotent on the PK). Only documents of THIS
 *  workspace are linked (PBA-L3c-005 defense in depth; callers validate visibility). */
export async function linkMessageAttachments(workspaceId: string, messageId: string, documentIds: string[]): Promise<void> {
  if (documentIds.length === 0) return;
  const own = await db()
    .select({ id: documents.id })
    .from(documents)
    .where(and(eq(documents.workspaceId, workspaceId), inArray(documents.id, documentIds)));
  if (own.length === 0) return;
  await db()
    .insert(messageAttachments)
    .values(own.map((d) => ({ workspaceId, messageId, documentId: d.id })))
    .onConflictDoNothing();
}

/** Attachments for one message (used to enrich the send response). */
export async function getMessageAttachments(workspaceId: string, messageId: string): Promise<MessageAttachment[]> {
  return (await attachmentsForMessages(workspaceId, [messageId])).get(messageId) ?? [];
}

function safeDecrypt(workspaceId: string, packed: string): string {
  try {
    return decryptField(workspaceId, packed);
  } catch {
    // Neutral placeholder — never surface a scary crypto error to the UI.
    return "⚠︎ couldn't decrypt this message";
  }
}

export interface ListOptions {
  afterSeq?: number;
  limit?: number;
}

/** Messages in a channel, ascending by seq. `afterSeq` powers incremental polling. */
export async function listMessages(
  workspaceId: string,
  channelId: string,
  opts: ListOptions = {},
): Promise<MessageRow[]> {
  const limit = Math.min(opts.limit ?? 200, 500);
  const where =
    opts.afterSeq != null
      ? and(eq(messages.workspaceId, workspaceId), eq(messages.channelId, channelId), gt(messages.seq, opts.afterSeq))
      : and(eq(messages.workspaceId, workspaceId), eq(messages.channelId, channelId));
  const rows = await db().select().from(messages).where(where).orderBy(asc(messages.seq)).limit(limit);
  const decoded = rows.map((r) => decode(workspaceId, r));
  const att = await attachmentsForMessages(workspaceId, decoded.map((m) => m.id));
  for (const m of decoded) m.attachments = att.get(m.id) ?? [];
  return decoded;
}

export interface SendInput {
  workspaceId: string;
  channelId: string;
  authorSub: string;
  body: string;
  fromAgent?: boolean;
  onBehalfOf?: string | null;
  threadId?: string | null;
  parentId?: string | null;
  clientMsgId?: string | null;
}

/** Append a message; `seq` is assigned atomically as max(seq)+1 for the channel. */
export async function sendMessage(input: SendInput): Promise<MessageRow> {
  const nextSeq = sql<number>`(SELECT COALESCE(MAX(${messages.seq}), 0) + 1 FROM ${messages} WHERE ${messages.channelId} = ${input.channelId})`;
  const [row] = await db()
    .insert(messages)
    .values({
      workspaceId: input.workspaceId,
      channelId: input.channelId,
      authorSub: input.authorSub,
      fromAgent: input.fromAgent ?? false,
      bodyEnc: encryptField(input.workspaceId, input.body),
      seq: nextSeq,
      threadId: input.threadId ?? null,
      parentId: input.parentId ?? null,
      onBehalfOf: input.onBehalfOf ?? null,
      clientMsgId: input.clientMsgId ?? null,
    })
    .returning();
  return decode(input.workspaceId, row!);
}

// ── pinned messages ──────────────────────────────────────────────────────────

/** Pin or unpin a message to its channel header. Returns the new pinned state. */
export async function setMessagePinned(workspaceId: string, channelId: string, messageId: string, pinned: boolean): Promise<boolean> {
  await db()
    .update(messages)
    .set({ pinned, pinnedAt: pinned ? new Date() : null })
    .where(and(eq(messages.workspaceId, workspaceId), eq(messages.channelId, channelId), eq(messages.id, messageId)));
  return pinned;
}

/** The channel's pinned messages (most-recently-pinned first), decoded with attachments. */
export async function listPinnedMessages(workspaceId: string, channelId: string): Promise<MessageRow[]> {
  const rows = await db()
    .select()
    .from(messages)
    .where(and(eq(messages.workspaceId, workspaceId), eq(messages.channelId, channelId), eq(messages.pinned, true), ne(messages.state, "deleted")))
    .orderBy(desc(messages.pinnedAt))
    .limit(50);
  const decoded = rows.map((r) => decode(workspaceId, r));
  const att = await attachmentsForMessages(workspaceId, decoded.map((m) => m.id));
  for (const m of decoded) m.attachments = att.get(m.id) ?? [];
  return decoded;
}
