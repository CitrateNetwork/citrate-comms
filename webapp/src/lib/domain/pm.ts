/**
 * Project-management repository — projects and tasks. The board is a status kanban
 * (Backlog → Todo → InProgress → InReview → Done); `ord` keeps within-column order.
 * Tasks can link to a conversation (linkedChannelId) — the cross-surface thread.
 */
import { and, asc, eq, inArray } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { projects, tasks, boards, boardColumns, taskRaci, members } from "@/lib/db/schema";
import { notifyTaskAssigned } from "./notifications";
import { upsertTaskDeadline } from "./calendar";
import { TASK_STATUSES, type TaskStatus } from "./enums";

export { TASK_STATUSES };
export type { TaskStatus };

export type RaciRole = "R" | "A" | "C" | "I";
export interface RaciAssignment {
  sub: string;
  role: RaciRole;
}

export interface ProjectRow {
  id: string;
  name: string;
  status: string;
}
export interface TaskRow {
  id: string;
  projectId: string | null;
  title: string;
  description: string | null;
  assigneeSub: string | null;
  status: TaskStatus;
  priority: string | null;
  due: string | null;
  ord: number;
  linkedChannelId: string | null;
}

export async function listProjects(workspaceId: string): Promise<ProjectRow[]> {
  return db()
    .select({ id: projects.id, name: projects.name, status: projects.status })
    .from(projects)
    .where(eq(projects.workspaceId, workspaceId))
    .orderBy(asc(projects.createdAt));
}

export async function createProject(workspaceId: string, name: string): Promise<ProjectRow> {
  const [row] = await db()
    .insert(projects)
    .values({ workspaceId, name: name.trim(), status: "active" })
    .returning({ id: projects.id, name: projects.name, status: projects.status });
  return row!;
}

export async function listTasks(workspaceId: string, projectId?: string): Promise<TaskRow[]> {
  const where = projectId
    ? and(eq(tasks.workspaceId, workspaceId), eq(tasks.projectId, projectId))
    : eq(tasks.workspaceId, workspaceId);
  const rows = await db().select().from(tasks).where(where).orderBy(asc(tasks.ord), asc(tasks.createdAt));
  return rows.map((r) => ({
    id: r.id,
    projectId: r.projectId,
    title: r.title,
    description: r.description,
    assigneeSub: r.assigneeSub,
    status: r.status as TaskStatus,
    priority: r.priority,
    due: r.due ? r.due.toISOString() : null,
    ord: r.ord,
    linkedChannelId: r.linkedChannelId,
  }));
}

export async function createTask(args: {
  workspaceId: string;
  projectId: string | null;
  title: string;
  assigneeSub?: string | null;
  priority?: string | null;
  due?: Date | null;
  /** Who created it — used to ping the assignee (skips self-assignment). */
  actorSub?: string;
}): Promise<TaskRow> {
  const [row] = await db()
    .insert(tasks)
    .values({
      workspaceId: args.workspaceId,
      projectId: args.projectId,
      title: args.title.trim(),
      status: "Backlog",
      assigneeSub: args.assigneeSub ?? null,
      priority: args.priority ?? null,
      due: args.due ?? null,
    })
    .returning();
  if (args.assigneeSub && args.actorSub) {
    await notifyTaskAssigned({ workspaceId: args.workspaceId, taskId: row!.id, assigneeSub: args.assigneeSub, actorSub: args.actorSub });
  }
  if (args.due) await syncTaskDeadline(args.workspaceId, row!.id, args.actorSub ?? args.assigneeSub ?? "system:pm");
  return {
    id: row!.id,
    projectId: row!.projectId,
    title: row!.title,
    description: row!.description,
    assigneeSub: row!.assigneeSub,
    status: row!.status as TaskStatus,
    priority: row!.priority,
    due: row!.due ? row!.due.toISOString() : null,
    ord: row!.ord,
    linkedChannelId: row!.linkedChannelId,
  };
}

/** Move a task to a new status column. */
export async function moveTask(workspaceId: string, taskId: string, status: TaskStatus): Promise<void> {
  await db()
    .update(tasks)
    .set({ status })
    .where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.id, taskId)));
}

/** Edit a task's content (Member+). When `assigneeSub` changes to a new member,
 *  pings them in their inbox (skipping self-assignment). `actorSub` = who edited. */
export async function updateTask(
  workspaceId: string,
  taskId: string,
  patch: { title?: string; priority?: string | null; assigneeSub?: string | null; due?: Date | null },
  actorSub?: string,
): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.title !== undefined) set.title = patch.title.trim();
  if (patch.priority !== undefined) set.priority = patch.priority || null;
  if (patch.due !== undefined) set.due = patch.due;

  let newAssignee: string | null = null;
  if (patch.assigneeSub !== undefined) {
    const next = patch.assigneeSub || null;
    set.assigneeSub = next;
    if (next) {
      const [cur] = await db().select({ a: tasks.assigneeSub }).from(tasks).where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.id, taskId))).limit(1);
      if ((cur?.a ?? null) !== next) newAssignee = next;
    }
  }

  if (Object.keys(set).length === 0) return;
  await db().update(tasks).set(set).where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.id, taskId)));

  if (newAssignee && actorSub) {
    await notifyTaskAssigned({ workspaceId, taskId, assigneeSub: newAssignee, actorSub });
  }
  // Keep the red calendar deadline in sync when the due date (or assignee/title) changes.
  if (patch.due !== undefined || patch.title !== undefined || patch.assigneeSub !== undefined) {
    await syncTaskDeadline(workspaceId, taskId, actorSub ?? "system:pm");
  }
}

// ── RACI + calendar-deadline bridge ──────────────────────────────────────────

/** Replace a task's RACI assignments. Empty array clears them. */
export async function setTaskRaci(workspaceId: string, taskId: string, assignments: RaciAssignment[], actorSub?: string): Promise<void> {
  await db().delete(taskRaci).where(and(eq(taskRaci.workspaceId, workspaceId), eq(taskRaci.taskId, taskId)));
  const seen = new Set<string>();
  const rows = assignments.filter((a) => a.sub && !seen.has(a.sub) && seen.add(a.sub)).map((a) => ({ workspaceId, taskId, sub: a.sub, role: a.role }));
  if (rows.length) await db().insert(taskRaci).values(rows);
  await syncTaskDeadline(workspaceId, taskId, actorSub ?? "system:pm");
}

export async function getTaskRaci(workspaceId: string, taskId: string): Promise<RaciAssignment[]> {
  const rows = await db().select({ sub: taskRaci.sub, role: taskRaci.role }).from(taskRaci).where(and(eq(taskRaci.workspaceId, workspaceId), eq(taskRaci.taskId, taskId)));
  return rows.map((r) => ({ sub: r.sub, role: r.role as RaciRole }));
}

/**
 * Mirror a task's deadline onto the calendar as a RED deadline event with RACI attendees.
 * Attendees = the RACI assignments; if none set, the task's assignee stands in as
 * Responsible so a plain assignment still calendars. No due date → the linked event is
 * cancelled. Best-effort.
 */
export async function syncTaskDeadline(workspaceId: string, taskId: string, actorSub: string): Promise<void> {
  try {
    const [t] = await db().select({ title: tasks.title, due: tasks.due, projectId: tasks.projectId, assigneeSub: tasks.assigneeSub }).from(tasks).where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.id, taskId))).limit(1);
    if (!t) return;
    let raci = await getTaskRaci(workspaceId, taskId);
    if (raci.length === 0 && t.assigneeSub) raci = [{ sub: t.assigneeSub, role: "R" }];
    // event timezone: the actor's (or first assignee's) member tz, else UTC
    const tzSub = actorSub.startsWith("system:") ? (raci[0]?.sub ?? "") : actorSub;
    const [mem] = tzSub ? await db().select({ timezone: members.timezone }).from(members).where(and(eq(members.workspaceId, workspaceId), eq(members.sub, tzSub))).limit(1) : [];
    await upsertTaskDeadline({
      workspaceId,
      taskId,
      projectId: t.projectId,
      title: t.title,
      due: t.due ?? null,
      timezone: mem?.timezone || "UTC",
      attendees: raci.map((r) => ({ sub: r.sub, raciRole: r.role })),
      createdBySub: actorSub.startsWith("system:") ? (raci[0]?.sub ?? t.assigneeSub ?? actorSub) : actorSub,
    });
  } catch {
    /* best-effort — the task write already succeeded */
  }
}

/** Delete a task (Owner/Admin). Cancels its linked calendar deadline; task_raci cascades. */
export async function deleteTask(workspaceId: string, taskId: string, actorSub?: string): Promise<void> {
  await upsertTaskDeadline({ workspaceId, taskId, projectId: null, title: "", due: null, timezone: "UTC", attendees: [], createdBySub: actorSub ?? "system:pm" }).catch(() => {});
  await db().delete(tasks).where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.id, taskId)));
}

/** Delete (kill) a project (Owner/Admin). Its tasks survive, unassigned; its board
 *  scaffolding is removed. */
export async function deleteProject(workspaceId: string, projectId: string): Promise<void> {
  const d = db();
  await d.update(tasks).set({ projectId: null }).where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.projectId, projectId)));
  const boardRows = await d.select({ id: boards.id }).from(boards).where(and(eq(boards.workspaceId, workspaceId), eq(boards.projectId, projectId)));
  const boardIds = boardRows.map((b) => b.id);
  if (boardIds.length > 0) await d.delete(boardColumns).where(inArray(boardColumns.boardId, boardIds));
  await d.delete(boards).where(and(eq(boards.workspaceId, workspaceId), eq(boards.projectId, projectId)));
  await d.delete(projects).where(and(eq(projects.workspaceId, workspaceId), eq(projects.id, projectId)));
}
