import { NextResponse } from "next/server";
import { Capability, requireCapability, requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { createTaskSchema, moveTaskSchema } from "@/lib/validation/schemas";
import { listTasks, createTask, moveTask, setTaskRaci } from "@/lib/domain/pm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireMember(req, id);
    const projectId = new URL(req.url).searchParams.get("projectId") ?? undefined;
    return NextResponse.json({ tasks: await listTasks(id, projectId) });
  } catch (e) {
    return errorResponse(e);
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = createTaskSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const task = await createTask({
      workspaceId: id,
      projectId: parsed.data.projectId ?? null,
      title: parsed.data.title,
      priority: parsed.data.priority ?? null,
      assigneeSub: parsed.data.assigneeSub ?? null,
      due: parsed.data.due ? new Date(parsed.data.due) : null,
      actorSub: ctx.sub,
    });
    if (parsed.data.raci?.length) await setTaskRaci(id, task.id, parsed.data.raci, ctx.sub);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "task_created", target: task.id });
    return NextResponse.json({ task }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Move a task to a new status column. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = moveTaskSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await moveTask(id, parsed.data.taskId, parsed.data.status);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "task_moved", target: `${parsed.data.taskId}:${parsed.data.status}` });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
