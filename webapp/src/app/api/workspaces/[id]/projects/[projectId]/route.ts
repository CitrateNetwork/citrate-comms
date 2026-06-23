import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { deleteProject } from "@/lib/domain/pm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

/** Delete (kill) a project (Owner/Admin via DeleteRecord). Its tasks survive,
 *  unassigned; the board scaffolding is removed. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; projectId: string }> }) {
  try {
    const { id, projectId } = await params;
    const ctx = await requireCapability(req, id, Capability.DeleteRecord);
    await deleteProject(id, projectId);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "project_deleted", target: projectId });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
