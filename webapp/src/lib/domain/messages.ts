/**
 * Message repository. Bodies are AES-256-GCM encrypted at rest with a per-workspace
 * key (lib/security/crypto.ts) — the honest trust boundary: the web tier CAN decrypt
 * (it holds the master key), unlike the native server-blind relay, but a raw DB dump
 * yields no plaintext. Each message gets a per-channel monotonic `seq` (the poll/SSE
 * cursor), assigned atomically inside the INSERT.
 */
import { and, asc, eq, gt, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { messages } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";

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
    createdAt: r.createdAt.toISOString(),
  };
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
  return rows.map((r) => decode(workspaceId, r));
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
