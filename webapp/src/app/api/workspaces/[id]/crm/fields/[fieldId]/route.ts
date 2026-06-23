import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmFieldDefUpdateSchema } from "@/lib/validation/schemas";
import { updateFieldDef, deleteFieldDef } from "@/lib/domain/crm-fields";

export const runtime = "nodejs";

/** Update a field definition (Owner/Admin). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; fieldId: string }> }) {
  try {
    const { id, fieldId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = crmFieldDefUpdateSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await updateFieldDef(id, fieldId, parsed.data, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Delete a field definition AND its stored values (Owner/Admin). */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; fieldId: string }> }) {
  try {
    const { id, fieldId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    await deleteFieldDef(id, fieldId, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
