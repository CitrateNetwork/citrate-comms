import { NextResponse } from "next/server";
import { requireMember, GuardError } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaPromptSchema } from "@/lib/validation/schemas";
import { setPromptLayer } from "@/lib/domain/personas";
import { canConfigurePersona } from "@/lib/domain/agent-config";

export const runtime = "nodejs";

/** Set (or clear, when content is blank) an editable prompt layer 1–4. Admin OR delegated configurer. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await canConfigurePersona(id, ctx.sub, ctx.role, personaId))) throw new GuardError(403, "not authorized to configure this persona");
    const parsed = personaPromptSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setPromptLayer(id, personaId, parsed.data.layer, parsed.data.content, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
