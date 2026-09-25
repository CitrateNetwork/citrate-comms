/**
 * Channel repository. Channels are workspace-scoped conversations (channel|forum|dm).
 * Listing is scoped to the caller's channel membership (Partner/Guest only see what
 * they're in; Owner/Admin/Member see workspace channels they belong to).
 */
import { and, eq, gt, inArray, ne, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { channels, channelMembers, messages, members } from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";

export interface ChannelRow {
  id: string;
  name: string;
  kind: "channel" | "forum" | "dm";
  topic: string | null;
  hasAgent: boolean;
}

/** Channels in a workspace the given member belongs to. */
export async function channelsForMember(workspaceId: string, sub: string): Promise<ChannelRow[]> {
  const rows = await db()
    .select({
      id: channels.id,
      name: channels.name,
      kind: channels.kind,
      topic: channels.topic,
      hasAgent: channels.hasAgent,
    })
    .from(channels)
    .innerJoin(channelMembers, eq(channelMembers.channelId, channels.id))
    .where(and(eq(channels.workspaceId, workspaceId), eq(channelMembers.sub, sub)));
  return rows.map((r) => ({ ...r, kind: r.kind as ChannelRow["kind"] }));
}

/** A single channel within a workspace (membership checked separately). */
export async function channelById(workspaceId: string, channelId: string): Promise<ChannelRow | null> {
  const [row] = await db()
    .select({
      id: channels.id,
      name: channels.name,
      kind: channels.kind,
      topic: channels.topic,
      hasAgent: channels.hasAgent,
    })
    .from(channels)
    .where(and(eq(channels.workspaceId, workspaceId), eq(channels.id, channelId)))
    .limit(1);
  return row ? { ...row, kind: row.kind as ChannelRow["kind"] } : null;
}

/** Resolve a channel's workspace (so channel-scoped routes can run the tenant guard). */
export async function channelWorkspace(channelId: string): Promise<string | null> {
  const [row] = await db()
    .select({ workspaceId: channels.workspaceId })
    .from(channels)
    .where(eq(channels.id, channelId))
    .limit(1);
  return row?.workspaceId ?? null;
}

/** Is `sub` a member of this channel? */
export async function isChannelMember(channelId: string, sub: string): Promise<boolean> {
  const [row] = await db()
    .select({ sub: channelMembers.sub })
    .from(channelMembers)
    .where(and(eq(channelMembers.channelId, channelId), eq(channelMembers.sub, sub)))
    .limit(1);
  return Boolean(row);
}

export interface CreateChannelInput {
  workspaceId: string;
  kind: "channel" | "forum" | "dm";
  name: string;
  topic?: string | null;
  createdBySub: string;
  /** Members to seat (the creator is always included). */
  memberSubs?: string[];
}

/** Create a channel and seat its initial members (creator always included). */
export async function createChannel(input: CreateChannelInput): Promise<ChannelRow> {
  const d = db();
  const [ch] = await d
    .insert(channels)
    .values({
      workspaceId: input.workspaceId,
      kind: input.kind,
      name: input.name.trim(),
      topic: input.topic ?? null,
      createdBySub: input.createdBySub,
    })
    .returning();
  const channel = ch!;

  // PBA-L3c-027: only ACTIVE members of this workspace can be seated — never an arbitrary
  // or foreign sub.
  const requested = Array.from(new Set(input.memberSubs ?? [])).filter((x) => x !== input.createdBySub);
  const active = requested.length
    ? (await d
        .select({ sub: members.sub })
        .from(members)
        .where(and(eq(members.workspaceId, input.workspaceId), eq(members.status, "active"), inArray(members.sub, requested))))
        .map((r) => r.sub)
    : [];
  const subs = [input.createdBySub, ...active];
  await d.insert(channelMembers).values(
    subs.map((sub) => ({ workspaceId: input.workspaceId, channelId: channel.id, sub })),
  );

  await appendAudit({
    workspaceId: input.workspaceId,
    actorSub: input.createdBySub,
    event: "channel_created",
    target: channel.id,
  });
  return { id: channel.id, name: channel.name, kind: channel.kind as ChannelRow["kind"], topic: channel.topic, hasAgent: channel.hasAgent };
}

/** Seat additional members on a channel (idempotent on the PK). */
export async function addChannelMembers(workspaceId: string, channelId: string, subs: string[]): Promise<void> {
  if (subs.length === 0) return;
  await db()
    .insert(channelMembers)
    .values(subs.map((sub) => ({ workspaceId, channelId, sub })))
    .onConflictDoNothing();
}

/** Mark a channel as having an agent member (drives the AGENT badge on the rail). */
export async function setChannelHasAgent(workspaceId: string, channelId: string, hasAgent: boolean): Promise<void> {
  await db()
    .update(channels)
    .set({ hasAgent })
    .where(and(eq(channels.workspaceId, workspaceId), eq(channels.id, channelId)));
}

/** Filter a set of subs to those already on the channel (avoids duplicate inserts upstream). */
export async function existingChannelMembers(channelId: string, subs: string[]): Promise<Set<string>> {
  if (subs.length === 0) return new Set();
  const rows = await db()
    .select({ sub: channelMembers.sub })
    .from(channelMembers)
    .where(and(eq(channelMembers.channelId, channelId), inArray(channelMembers.sub, subs)));
  return new Set(rows.map((r) => r.sub));
}

// ── read state / unread counts ───────────────────────────────────────────────

/** Advance a member's read cursor for a channel to `seq` (monotonic — never rewinds). */
export async function markChannelRead(workspaceId: string, channelId: string, sub: string, seq: number): Promise<void> {
  await db()
    .update(channelMembers)
    .set({ lastReadSeq: sql`GREATEST(${channelMembers.lastReadSeq}, ${seq})` })
    .where(and(eq(channelMembers.workspaceId, workspaceId), eq(channelMembers.channelId, channelId), eq(channelMembers.sub, sub)));
}

/**
 * Unread message count per channel for a member, across all channels they belong to.
 * Unread = live messages (not deleted) authored by someone else with seq beyond the
 * member's read cursor. One query; channels with nothing unread come back as 0.
 */
export async function unreadCounts(workspaceId: string, sub: string): Promise<Map<string, number>> {
  const rows = await db()
    .select({ channelId: channelMembers.channelId, unread: sql<number>`count(${messages.id})::int` })
    .from(channelMembers)
    .leftJoin(
      messages,
      and(
        eq(messages.channelId, channelMembers.channelId),
        gt(messages.seq, channelMembers.lastReadSeq),
        ne(messages.authorSub, sub),
        ne(messages.state, "deleted"),
      ),
    )
    .where(and(eq(channelMembers.workspaceId, workspaceId), eq(channelMembers.sub, sub)))
    .groupBy(channelMembers.channelId);
  const out = new Map<string, number>();
  for (const r of rows) out.set(r.channelId, Number(r.unread) || 0);
  return out;
}
