import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaImportSchema } from "@/lib/validation/schemas";
import { importPersona } from "@/lib/domain/personas";

export const runtime = "nodejs";

/** Import a persona from exported JSON as a new editable persona. Owner/Admin. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = personaImportSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const newId = await importPersona(id, parsed.data, ctx.sub);
    return NextResponse.json({ personaId: newId }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
