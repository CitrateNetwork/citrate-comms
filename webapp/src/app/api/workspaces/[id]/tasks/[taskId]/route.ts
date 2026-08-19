import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { editTaskSchema } from "@/lib/validation/schemas";
import { updateTask, deleteTask, setTaskRaci } from "@/lib/domain/pm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

/** Edit a task (Member+ via CreateRecord). Supports due date + RACI (calendared as a red deadline). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; taskId: string }> }) {
  try {
    const { id, taskId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = editTaskSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const { raci, due, ...rest } = parsed.data;
    await updateTask(id, taskId, { ...rest, ...(due !== undefined ? { due: due ? new Date(due) : null } : {}) }, ctx.sub);
    if (raci !== undefined) await setTaskRaci(id, taskId, raci, ctx.sub);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "task_edited", target: taskId });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Delete a task (Owner/Admin via DeleteRecord). */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; taskId: string }> }) {
  try {
    const { id, taskId } = await params;
    const ctx = await requireCapability(req, id, Capability.DeleteRecord);
    await deleteTask(id, taskId, ctx.sub);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "task_deleted", target: taskId });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
