/**
 * Agent chat thread + message persistence (COMMS-AGENTS build-spec §8). Threads scope
 * a human↔persona conversation to a workspace (and optionally a channel/deal/account).
 * Message content is AES-256-GCM encrypted per-workspace at rest (lib/security/crypto),
 * the same posture as channel messages. The tool-trace is stored alongside the
 * assistant turn so the panel can replay which tools ran.
 */
import { and, asc, desc, eq, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agentThreads, agentMessages } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";

export interface AgentThreadRow {
  id: string;
  personaId: string | null;
  title: string;
  channelId: string | null;
  dealId: string | null;
  invokedBySub: string;
  createdAt: string;
}

export interface AgentMessageRow {
  id: string;
  role: string;
  content: string;
  toolTrace: unknown;
  seq: number;
  createdAt: string;
}

export interface ThreadScope {
  channelId?: string | null;
  dealId?: string | null;
  accountId?: string | null;
}

/** Create a thread (optionally with a caller-supplied id for client-stable continuity). */
export async function createAgentThread(args: {
  workspaceId: string;
  personaId: string;
  invokedBySub: string;
  title: string;
  id?: string;
  scope?: ThreadScope;
}): Promise<string | null> {
  try {
    const [row] = await db()
      .insert(agentThreads)
      .values({
        ...(args.id ? { id: args.id } : {}),
        workspaceId: args.workspaceId,
        personaId: args.personaId,
        invokedBySub: args.invokedBySub,
        title: args.title.slice(0, 200),
        channelId: args.scope?.channelId ?? null,
        dealId: args.scope?.dealId ?? null,
        accountId: args.scope?.accountId ?? null,
      })
      .returning({ id: agentThreads.id });
    return row?.id ?? null;
  } catch {
    return null;
  }
}

/** Does this thread belong to this user in this workspace? */
export async function ownsAgentThread(workspaceId: string, sub: string, threadId: string): Promise<boolean> {
  const [r] = await db()
    .select({ id: agentThreads.id })
    .from(agentThreads)
    .where(and(eq(agentThreads.workspaceId, workspaceId), eq(agentThreads.id, threadId), eq(agentThreads.invokedBySub, sub)))
    .limit(1);
  return Boolean(r);
}

/**
 * Resolve the thread to use: continue the caller's thread if they own it, else create
 * one (using the supplied id when present so the client keeps a stable conversation).
 */
export async function getOrCreateThread(args: {
  workspaceId: string;
  personaId: string;
  invokedBySub: string;
  title: string;
  threadId?: string;
  scope?: ThreadScope;
}): Promise<string | null> {
  if (args.threadId && (await ownsAgentThread(args.workspaceId, args.invokedBySub, args.threadId))) {
    return args.threadId;
  }
  return createAgentThread({
    workspaceId: args.workspaceId,
    personaId: args.personaId,
    invokedBySub: args.invokedBySub,
    title: args.title,
    id: args.threadId,
    scope: args.scope,
  });
}

/** Append a message to a thread; `seq` is max(seq)+1 within the thread. */
export async function appendAgentMessage(args: {
  workspaceId: string;
  threadId: string;
  role: "user" | "assistant" | "tool";
  content: string;
  toolTrace?: unknown;
}): Promise<void> {
  const nextSeq = sql<number>`(SELECT COALESCE(MAX(${agentMessages.seq}), 0) + 1 FROM ${agentMessages} WHERE ${agentMessages.threadId} = ${args.threadId})`;
  try {
    await db().insert(agentMessages).values({
      workspaceId: args.workspaceId,
      threadId: args.threadId,
      role: args.role,
      contentEnc: encryptField(args.workspaceId, args.content),
      toolTraceJson: args.toolTrace ?? null,
      seq: nextSeq,
    });
  } catch {
    /* persistence is best-effort — never break the stream */
  }
}

export async function listThreadMessages(workspaceId: string, threadId: string): Promise<AgentMessageRow[]> {
  const rows = await db()
    .select()
    .from(agentMessages)
    .where(and(eq(agentMessages.workspaceId, workspaceId), eq(agentMessages.threadId, threadId)))
    .orderBy(asc(agentMessages.seq));
  return rows.map((r) => ({
    id: r.id,
    role: r.role,
    content: safeDecrypt(workspaceId, r.contentEnc),
    toolTrace: r.toolTraceJson,
    seq: r.seq,
    createdAt: r.createdAt.toISOString(),
  }));
}

/** Recent threads for a user (the agent panel's history list), optionally per persona. */
export async function listAgentThreads(
  workspaceId: string,
  sub: string,
  opts: { personaId?: string; limit?: number } = {},
): Promise<AgentThreadRow[]> {
  const conds = [eq(agentThreads.workspaceId, workspaceId), eq(agentThreads.invokedBySub, sub)];
  if (opts.personaId) conds.push(eq(agentThreads.personaId, opts.personaId));
  const rows = await db()
    .select()
    .from(agentThreads)
    .where(and(...conds))
    .orderBy(desc(agentThreads.createdAt))
    .limit(opts.limit ?? 30);
  return rows.map((r) => ({
    id: r.id,
    personaId: r.personaId,
    title: r.title,
    channelId: r.channelId,
    dealId: r.dealId,
    invokedBySub: r.invokedBySub,
    createdAt: r.createdAt.toISOString(),
  }));
}

function safeDecrypt(workspaceId: string, packed: string): string {
  try {
    return decryptField(workspaceId, packed);
  } catch {
    return "⚠︎ couldn't decrypt";
  }
}
