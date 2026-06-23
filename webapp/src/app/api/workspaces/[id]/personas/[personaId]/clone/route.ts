import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaCloneSchema } from "@/lib/validation/schemas";
import { clonePersona } from "@/lib/domain/personas";

export const runtime = "nodejs";

/** Clone a persona (template or custom) into a new editable persona. Owner/Admin. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = personaCloneSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const newId = await clonePersona(id, personaId, parsed.data.name, ctx.sub);
    if (!newId) return NextResponse.json({ error: "not_found" }, { status: 404 });
    return NextResponse.json({ personaId: newId }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
