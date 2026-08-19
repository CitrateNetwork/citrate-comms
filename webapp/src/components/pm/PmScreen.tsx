"use client";

/**
 * Projects — a task kanban (Backlog → Todo → InProgress → InReview → Done). Drag a
 * task between columns to change its status (persisted + audited). Tasks can belong
 * to a project; the project filter scopes the board.
 */
import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Avatar, Btn, Icon, RiskBadge } from "@/components/primitives";
import { Kanban, type KanbanColumn } from "@/components/board/Kanban";
import type { TaskStatus } from "@/lib/domain/enums";
import s from "@/components/common/screen.module.css";

/** ISO → value for <input type="datetime-local"> in the browser's local time ("" if none). */
function dueToLocalInput(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export interface UiProject {
  id: string;
  name: string;
}
export interface UiTask {
  id: string;
  column: string; // status
  projectId: string | null;
  title: string;
  priority: string | null;
  due: string | null; // ISO; mirrored to a red calendar deadline
  assigneeSub: string | null;
  assigneeName: string | null;
}
export interface UiMember {
  sub: string;
  name: string;
}

const CARD_BTN: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 20,
  height: 20,
  borderRadius: 4,
  border: "1px solid var(--border-2)",
  background: "var(--paper-pure)",
  color: "var(--fg-3)",
  cursor: "pointer",
};

const COLUMNS: KanbanColumn[] = [
  { key: "Backlog", label: "Backlog", accent: "var(--stone-400)" },
  { key: "Todo", label: "To do", accent: "var(--info)" },
  { key: "InProgress", label: "In progress", accent: "var(--citrate-yellow-deep)" },
  { key: "InReview", label: "In review", accent: "var(--citrate-green-deep)" },
  { key: "Done", label: "Done", accent: "var(--success)" },
];

export function PmScreen({
  workspaceId,
  canEdit,
  canDelete = false,
  projects,
  members = [],
  tasks,
}: {
  workspaceId: string;
  canEdit: boolean;
  canDelete?: boolean;
  projects: UiProject[];
  members?: UiMember[];
  tasks: UiTask[];
}) {
  const router = useRouter();
  // Inbox "task_assigned" links land here as ?task=<id> — focus + highlight that card.
  const focusId = useSearchParams()?.get("task") ?? null;
  useEffect(() => {
    if (!focusId) return;
    const el = document.getElementById(`task-card-${focusId}`);
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [focusId]);
  const [taskList, setTaskList] = useState<UiTask[]>(tasks);
  const [filter, setFilter] = useState<string>("all");
  const [newProject, setNewProject] = useState(false);
  const [newTask, setNewTask] = useState(false);
  const [editTask, setEditTask] = useState<UiTask | null>(null);

  const visible = useMemo(
    () => (filter === "all" ? taskList : taskList.filter((t) => t.projectId === filter)),
    [taskList, filter],
  );

  async function move(taskId: string, toStatus: string) {
    setTaskList((prev) => prev.map((t) => (t.id === taskId ? { ...t, column: toStatus } : t)));
    await fetch(`/api/workspaces/${workspaceId}/tasks`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ taskId, status: toStatus as TaskStatus }),
    }).catch(() => router.refresh());
  }

  async function delTask(taskId: string) {
    if (!confirm("Delete this task? This can't be undone.")) return;
    const prev = taskList;
    setTaskList((p) => p.filter((t) => t.id !== taskId));
    const r = await fetch(`/api/workspaces/${workspaceId}/tasks/${taskId}`, { method: "DELETE" });
    if (!r.ok) {
      setTaskList(prev);
      router.refresh();
    }
  }

  async function delProject(projectId: string) {
    if (!confirm("Delete this project? Its tasks are kept (unassigned). This can't be undone.")) return;
    const r = await fetch(`/api/workspaces/${workspaceId}/projects/${projectId}`, { method: "DELETE" });
    if (r.ok) {
      setFilter("all");
      router.refresh();
    }
  }

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <div className={s.eyebrow}>Workspace</div>
          <h1 className={s.title}>Projects</h1>
        </div>
        <div className={s.headActions}>
          {projects.length > 0 && (
            <select className={s.input} value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: "auto" }}>
              <option value="all">All projects</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          )}
          {canDelete && filter !== "all" && (
            <Btn variant="ghost" size="sm" icon="x" onClick={() => delProject(filter)}>
              Delete project
            </Btn>
          )}
          {canEdit && (
            <>
              <Btn variant="ghost" icon="plus" onClick={() => setNewProject(true)}>
                New project
              </Btn>
              <Btn variant="primary" icon="plus" onClick={() => setNewTask(true)}>
                New task
              </Btn>
            </>
          )}
        </div>
      </header>

      <Kanban
        columns={COLUMNS}
        items={visible}
        emptyHint="No tasks"
        onMove={canEdit ? move : () => {}}
        renderCard={(t) => (
          <div
            id={`task-card-${t.id}`}
            style={{
              position: "relative",
              display: "flex",
              flexDirection: "column",
              gap: "var(--s-2)",
              ...(t.id === focusId
                ? { outline: "2px solid var(--citrate-green-deep)", outlineOffset: 3, borderRadius: "var(--r-1)" }
                : null),
            }}
          >
            <div style={{ fontWeight: 600, fontSize: "var(--t-sm)", paddingRight: canEdit || canDelete ? 40 : 0 }}>{t.title}</div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              {t.priority ? <RiskBadge level={t.priority as "low" | "medium" | "high"} /> : <span />}
              {t.assigneeName && <Avatar name={t.assigneeName} size="sm" />}
            </div>
            {(canEdit || canDelete) && (
              <div style={{ position: "absolute", top: 0, right: 0, display: "flex", gap: 4 }}>
                {canEdit && (
                  <button
                    style={CARD_BTN}
                    title="Edit task"
                    aria-label="Edit task"
                    onClick={(e) => { e.preventDefault(); e.stopPropagation(); setEditTask(t); }}
                  >
                    <Icon name="settings" size={12} />
                  </button>
                )}
                {canDelete && (
                  <button
                    style={CARD_BTN}
                    title="Delete task"
                    aria-label="Delete task"
                    onClick={(e) => { e.preventDefault(); e.stopPropagation(); void delTask(t.id); }}
                  >
                    <Icon name="x" size={12} />
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      />

      {newProject && (
        <SimpleCreate
          title="New project"
          label="Project name"
          onClose={() => setNewProject(false)}
          onSubmit={async (name) => {
            const r = await fetch(`/api/workspaces/${workspaceId}/projects`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ name }),
            });
            if (r.ok) router.refresh();
          }}
        />
      )}
      {newTask && (
        <TaskDialog
          workspaceId={workspaceId}
          projects={projects}
          defaultProject={filter === "all" ? "" : filter}
          onClose={() => setNewTask(false)}
          onCreated={(t) => {
            setTaskList((prev) => [...prev, t]);
            setNewTask(false);
          }}
        />
      )}
      {editTask && (
        <TaskEditDialog
          workspaceId={workspaceId}
          task={editTask}
          members={members}
          onClose={() => setEditTask(null)}
          onSaved={(patch) => {
            setTaskList((prev) => prev.map((t) => (t.id === editTask.id ? { ...t, ...patch } : t)));
            setEditTask(null);
          }}
        />
      )}
    </div>
  );
}

function TaskEditDialog({
  workspaceId,
  task,
  members,
  onClose,
  onSaved,
}: {
  workspaceId: string;
  task: UiTask;
  members: UiMember[];
  onClose: () => void;
  onSaved: (patch: { title: string; priority: string | null; assigneeSub: string | null; due: string | null; assigneeName: string | null }) => void;
}) {
  const [title, setTitle] = useState(task.title);
  const [priority, setPriority] = useState<string>(task.priority ?? "");
  const [assigneeSub, setAssigneeSub] = useState<string>(task.assigneeSub ?? "");
  const [due, setDue] = useState<string>(dueToLocalInput(task.due));
  const [busy, setBusy] = useState(false);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim() || busy) return;
    setBusy(true);
    const dueISO = due ? new Date(due).toISOString() : null;
    const body = { title: title.trim(), priority: priority || null, assigneeSub: assigneeSub || null, due: dueISO };
    const r = await fetch(`/api/workspaces/${workspaceId}/tasks/${task.id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    setBusy(false);
    if (r.ok) {
      const assigneeName = assigneeSub ? members.find((m) => m.sub === assigneeSub)?.name ?? null : null;
      onSaved({ ...body, assigneeName });
    }
  }

  return (
    <div className={s.scrim} onClick={onClose}>
      <div className={s.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={s.dialogHead}>Edit task</div>
        <form className={s.form} onSubmit={save}>
          <label className={s.field}>
            <span className={s.fieldLabel}>Title</span>
            <input className={s.input} value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Priority</span>
            <select className={s.input} value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="">None</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
            </select>
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Assignee</span>
            <select className={s.input} value={assigneeSub} onChange={(e) => setAssigneeSub(e.target.value)}>
              <option value="">Unassigned</option>
              {members.map((m) => (
                <option key={m.sub} value={m.sub}>{m.name}</option>
              ))}
            </select>
            <span className={s.fieldHint}>Assigning a member drops a task in their inbox.</span>
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Deadline</span>
            <input className={s.input} type="datetime-local" value={due} onChange={(e) => setDue(e.target.value)} />
            <span className={s.fieldHint}>A deadline shows in red on the assignee&apos;s calendar and reminds them ahead of time.</span>
          </label>
          <div className={s.dialogFoot}>
            <Btn variant="quiet" type="button" onClick={onClose}>
              Cancel
            </Btn>
            <Btn variant="primary" type="submit" disabled={busy || !title.trim()}>
              {busy ? "Saving…" : "Save"}
            </Btn>
          </div>
        </form>
      </div>
    </div>
  );
}

function SimpleCreate({
  title,
  label,
  onClose,
  onSubmit,
}: {
  title: string;
  label: string;
  onClose: () => void;
  onSubmit: (value: string) => Promise<void>;
}) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!value.trim() || busy) return;
    setBusy(true);
    await onSubmit(value.trim());
    setBusy(false);
    onClose();
  }
  return (
    <div className={s.scrim} onClick={onClose}>
      <div className={s.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={s.dialogHead}>{title}</div>
        <form className={s.form} onSubmit={submit}>
          <label className={s.field}>
            <span className={s.fieldLabel}>{label}</span>
            <input className={s.input} value={value} onChange={(e) => setValue(e.target.value)} autoFocus />
          </label>
          <div className={s.dialogFoot}>
            <Btn variant="quiet" type="button" onClick={onClose}>
              Cancel
            </Btn>
            <Btn variant="primary" type="submit" disabled={busy || !value.trim()}>
              Create
            </Btn>
          </div>
        </form>
      </div>
    </div>
  );
}

function TaskDialog({
  workspaceId,
  projects,
  defaultProject,
  onClose,
  onCreated,
}: {
  workspaceId: string;
  projects: UiProject[];
  defaultProject: string;
  onClose: () => void;
  onCreated: (t: UiTask) => void;
}) {
  const [title, setTitle] = useState("");
  const [projectId, setProjectId] = useState(defaultProject);
  const [priority, setPriority] = useState<string>("");
  const [busy, setBusy] = useState(false);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim() || busy) return;
    setBusy(true);
    const r = await fetch(`/api/workspaces/${workspaceId}/tasks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        title: title.trim(),
        projectId: projectId || undefined,
        priority: priority || undefined,
      }),
    });
    setBusy(false);
    if (r.ok) {
      const { task } = (await r.json()) as { task: { id: string; projectId: string | null; title: string; priority: string | null; due?: string | null } };
      onCreated({ id: task.id, column: "Backlog", projectId: task.projectId, title: task.title, priority: task.priority, due: task.due ?? null, assigneeSub: null, assigneeName: null });
    }
  }
  return (
    <div className={s.scrim} onClick={onClose}>
      <div className={s.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={s.dialogHead}>New task</div>
        <form className={s.form} onSubmit={create}>
          <label className={s.field}>
            <span className={s.fieldLabel}>Title</span>
            <input className={s.input} value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Project (optional)</span>
            <select className={s.input} value={projectId} onChange={(e) => setProjectId(e.target.value)}>
              <option value="">No project</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Priority (optional)</span>
            <select className={s.input} value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="">None</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </label>
          <div className={s.dialogFoot}>
            <Btn variant="quiet" type="button" onClick={onClose}>
              Cancel
            </Btn>
            <Btn variant="primary" type="submit" disabled={busy || !title.trim()}>
              Create task
            </Btn>
          </div>
        </form>
      </div>
    </div>
  );
}
