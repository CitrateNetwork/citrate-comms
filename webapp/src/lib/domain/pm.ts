/**
 * Project-management repository — projects and tasks. The board is a status kanban
 * (Backlog → Todo → InProgress → InReview → Done); `ord` keeps within-column order.
 * Tasks can link to a conversation (linkedChannelId) — the cross-surface thread.
 */
import { and, asc, eq, inArray } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { projects, tasks, boards, boardColumns } from "@/lib/db/schema";
import { TASK_STATUSES, type TaskStatus } from "./enums";

export { TASK_STATUSES };
export type { TaskStatus };

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
    })
    .returning();
  return {
    id: row!.id,
    projectId: row!.projectId,
    title: row!.title,
    description: row!.description,
    assigneeSub: row!.assigneeSub,
    status: row!.status as TaskStatus,
    priority: row!.priority,
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

/** Edit a task's content (Member+). */
export async function updateTask(
  workspaceId: string,
  taskId: string,
  patch: { title?: string; priority?: string | null },
): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.title !== undefined) set.title = patch.title.trim();
  if (patch.priority !== undefined) set.priority = patch.priority || null;
  if (Object.keys(set).length === 0) return;
  await db().update(tasks).set(set).where(and(eq(tasks.workspaceId, workspaceId), eq(tasks.id, taskId)));
}

/** Delete a task (Owner/Admin). */
export async function deleteTask(workspaceId: string, taskId: string): Promise<void> {
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
