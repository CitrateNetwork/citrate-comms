import { NextResponse } from "next/server";
import { requireMember, GuardError } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { canConfigurePersona, setResourceEnabled, deleteResource } from "@/lib/domain/agent-config";

export const runtime = "nodejs";

/** Enable/disable a persona resource. Admin OR a delegated configurer. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; personaId: string; resourceId: string }> }) {
  try {
    const { id, personaId, resourceId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await canConfigurePersona(id, ctx.sub, ctx.role, personaId))) throw new GuardError(403, "not authorized");
    const body = (await readJson(req)) as { enabled?: unknown };
    await setResourceEnabled(id, personaId, resourceId, body.enabled === true, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Delete a persona resource. Admin OR a delegated configurer. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; personaId: string; resourceId: string }> }) {
  try {
    const { id, personaId, resourceId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await canConfigurePersona(id, ctx.sub, ctx.role, personaId))) throw new GuardError(403, "not authorized");
    await deleteResource(id, personaId, resourceId, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
