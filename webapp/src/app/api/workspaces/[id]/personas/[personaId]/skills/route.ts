import { NextResponse } from "next/server";
import { requireMember, GuardError } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaSkillSchema } from "@/lib/validation/schemas";
import { setSkillEnabled } from "@/lib/domain/personas";
import { canConfigurePersona } from "@/lib/domain/agent-config";

export const runtime = "nodejs";

/** Toggle an agentile skill on/off for a persona. Admin OR delegated configurer. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await canConfigurePersona(id, ctx.sub, ctx.role, personaId))) throw new GuardError(403, "not authorized to configure this persona");
    const parsed = personaSkillSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setSkillEnabled(id, personaId, parsed.data.skillKey, parsed.data.enabled);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
