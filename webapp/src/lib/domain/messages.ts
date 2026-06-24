/**
 * Message repository. Bodies are AES-256-GCM encrypted at rest with a per-workspace
 * key (lib/security/crypto.ts) — the honest trust boundary: the web tier CAN decrypt
 * (it holds the master key), unlike the native server-blind relay, but a raw DB dump
 * yields no plaintext. Each message gets a per-channel monotonic `seq` (the poll/SSE
 * cursor), assigned atomically inside the INSERT.
 */
import { and, asc, eq, gt, inArray, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { messages, messageAttachments, documents } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";

export interface MessageAttachment {
  id: string;
  name: string;
  mime: string | null;
  url: string; // raw Blob URL (display); downloads go through the audited proxy
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
    .where(and(eq(messageAttachments.workspaceId, workspaceId), inArray(messageAttachments.messageId, messageIds)));
  for (const r of rows) {
    const list = out.get(r.messageId) ?? [];
    list.push({ id: r.id, name: r.name, mime: r.mime, url: r.blobUrl });
    out.set(r.messageId, list);
  }
  return out;
}

/** Link uploaded documents to a message (idempotent on the PK). */
export async function linkMessageAttachments(workspaceId: string, messageId: string, documentIds: string[]): Promise<void> {
  if (documentIds.length === 0) return;
  await db()
    .insert(messageAttachments)
    .values(documentIds.map((documentId) => ({ workspaceId, messageId, documentId })))
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
