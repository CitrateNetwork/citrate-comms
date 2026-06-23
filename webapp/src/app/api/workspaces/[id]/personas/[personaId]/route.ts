import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaUpdateSchema } from "@/lib/validation/schemas";
import { getPersonaConfig, updatePersona, deletePersona, exportPersona } from "@/lib/domain/personas";
import type { ToolName } from "@/lib/ai/personas";

export const runtime = "nodejs";

/** Persona editor config (or ?export=1 → portable JSON). Owner/Admin. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    await requireCapability(req, id, Capability.ManageWorkspace);
    if (new URL(req.url).searchParams.get("export") === "1") {
      const exp = await exportPersona(id, personaId);
      if (!exp) return NextResponse.json({ error: "not_found" }, { status: 404 });
      return NextResponse.json({ persona: exp });
    }
    const cfg = await getPersonaConfig(id, personaId);
    if (!cfg) return NextResponse.json({ error: "not_found" }, { status: 404 });
    return NextResponse.json({ config: cfg });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Update model/tools/steps/temperature/name/enabled. Owner/Admin. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = personaUpdateSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await updatePersona(id, personaId, { ...parsed.data, tools: parsed.data.tools as ToolName[] | undefined }, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Delete a non-template persona. Owner/Admin. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const res = await deletePersona(id, personaId, ctx.sub);
    if (!res.ok) return NextResponse.json({ error: res.error }, { status: res.error === "template_protected" ? 409 : 404 });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
