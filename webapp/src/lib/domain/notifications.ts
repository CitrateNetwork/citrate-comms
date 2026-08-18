/**
 * MEN-2 — notifications (pings). An @-mention of a member in a channel creates a
 * notification for that member. We store NO message content (bodies are encrypted at rest);
 * the recipient follows the link to read it in context. Read state is per-row (readAt).
 */
import { and, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { notifications, channels, members } from "@/lib/db/schema";
import { directory } from "@/lib/domain/members";
import { parseMentions, type Mentionable } from "@/lib/mentions";
import { emitNotify, toNotificationEvent } from "@/lib/realtime/notify-events";

export interface NotificationRow {
  id: string;
  kind: string;
  actorSub: string | null;
  actorName: string | null;
  channelId: string | null;
  channelName: string | null;
  messageId: string | null;
  taskId: string | null;
  read: boolean;
  createdAt: string;
}

/**
 * Create mention notifications for the human members named in `body`. The actor never
 * notifies themselves. Best-effort — never breaks the message send.
 */
export async function notifyChannelMentions(args: {
  workspaceId: string;
  channelId: string;
  messageId: string;
  body: string;
  actorSub: string;
}): Promise<void> {
  try {
    if (!args.body || !args.body.includes("@")) return;
    const dir = await directory(args.workspaceId);
    const candidates: Mentionable[] = Object.entries(dir)
      .filter(([, e]) => !e.isAgent)
      .map(([sub, e]) => ({ id: sub, name: e.displayName, sub, kind: "member" as const }));
    const { members: mentioned } = parseMentions(args.body, candidates);
    const recipients = mentioned.map((m) => m.sub).filter((s) => s !== args.actorSub);
    if (recipients.length === 0) return;
    const inserted = await db()
      .insert(notifications)
      .values(
        recipients.map((recipientSub) => ({
          workspaceId: args.workspaceId,
          recipientSub,
          kind: "mention",
          actorSub: args.actorSub,
          channelId: args.channelId,
          messageId: args.messageId,
        })),
      )
      .returning({ id: notifications.id, recipientSub: notifications.recipientSub, createdAt: notifications.createdAt });
    // E-5 WP-1: push metadata (NEVER the body) to any live SSE streams on this
    // instance. `toNotificationEvent` whitelists keys, so nothing content-bearing
    // can ride along. Cross-instance streams reconcile via their periodic re-check.
    const [ch] = await db().select({ name: channels.name }).from(channels).where(eq(channels.id, args.channelId)).limit(1);
    const actorName = dir[args.actorSub]?.displayName ?? null;
    for (const row of inserted) {
      emitNotify(
        args.workspaceId,
        row.recipientSub,
        toNotificationEvent({
          id: row.id,
          kind: "mention",
          actorName,
          channelId: args.channelId,
          channelName: ch?.name ?? null,
          createdAt: row.createdAt.toISOString(),
        }),
      );
    }
  } catch {
    /* notifications are best-effort */
  }
}

export async function listNotifications(workspaceId: string, sub: string, limit = 30): Promise<NotificationRow[]> {
  const rows = await db()
    .select({
      id: notifications.id,
      kind: notifications.kind,
      actorSub: notifications.actorSub,
      channelId: notifications.channelId,
      messageId: notifications.messageId,
      taskId: notifications.taskId,
      readAt: notifications.readAt,
      createdAt: notifications.createdAt,
      channelName: channels.name,
      actorName: members.displayName,
    })
    .from(notifications)
    .leftJoin(channels, eq(channels.id, notifications.channelId))
    .leftJoin(members, and(eq(members.workspaceId, notifications.workspaceId), eq(members.sub, notifications.actorSub)))
    .where(and(eq(notifications.workspaceId, workspaceId), eq(notifications.recipientSub, sub)))
    .orderBy(desc(notifications.createdAt))
    .limit(Math.min(Math.max(limit, 1), 100));
  return rows.map((r) => ({
    id: r.id,
    kind: r.kind,
    actorSub: r.actorSub,
    actorName: r.actorName ?? null,
    channelId: r.channelId,
    channelName: r.channelName ?? null,
    messageId: r.messageId,
    taskId: r.taskId,
    read: r.readAt != null,
    createdAt: r.createdAt.toISOString(),
  }));
}

/**
 * Notify a member that a task was assigned to them. No content stored (parity with
 * mentions) — the recipient follows the link to the board. Skips self-assignment.
 * Best-effort: never breaks the task write.
 */
export async function notifyTaskAssigned(args: {
  workspaceId: string;
  taskId: string;
  assigneeSub: string;
  actorSub: string;
}): Promise<void> {
  try {
    if (!args.assigneeSub || args.assigneeSub === args.actorSub) return;
    const [row] = await db()
      .insert(notifications)
      .values({
        workspaceId: args.workspaceId,
        recipientSub: args.assigneeSub,
        kind: "task_assigned",
        actorSub: args.actorSub,
        taskId: args.taskId,
      })
      .returning({ id: notifications.id, createdAt: notifications.createdAt });
    const dir = await directory(args.workspaceId);
    emitNotify(
      args.workspaceId,
      args.assigneeSub,
      toNotificationEvent({
        id: row!.id,
        kind: "task_assigned",
        actorName: dir[args.actorSub]?.displayName ?? null,
        channelId: null,
        channelName: null,
        taskId: args.taskId,
        createdAt: row!.createdAt.toISOString(),
      }),
    );
  } catch {
    /* notifications are best-effort */
  }
}

export async function unreadCount(workspaceId: string, sub: string): Promise<number> {
  const [r] = await db()
    .select({ n: sql<number>`count(*)::int` })
    .from(notifications)
    .where(and(eq(notifications.workspaceId, workspaceId), eq(notifications.recipientSub, sub), isNull(notifications.readAt)));
  return r?.n ?? 0;
}

/** Mark specific notifications (or all of the caller's) as read. Scoped to the recipient. */
export async function markRead(workspaceId: string, sub: string, opts: { ids?: string[]; all?: boolean }): Promise<void> {
  const base = and(eq(notifications.workspaceId, workspaceId), eq(notifications.recipientSub, sub), isNull(notifications.readAt));
  if (opts.all) {
    await db().update(notifications).set({ readAt: new Date() }).where(base);
  } else if (opts.ids && opts.ids.length > 0) {
    await db()
      .update(notifications)
      .set({ readAt: new Date() })
      .where(and(base, inArray(notifications.id, opts.ids)));
  }
}
