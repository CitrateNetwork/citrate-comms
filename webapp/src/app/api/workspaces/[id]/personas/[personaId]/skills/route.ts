import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaSkillSchema } from "@/lib/validation/schemas";
import { setSkillEnabled } from "@/lib/domain/personas";

export const runtime = "nodejs";

/** Toggle an agentile skill on/off for a persona. Owner/Admin. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = personaSkillSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setSkillEnabled(id, personaId, parsed.data.skillKey, parsed.data.enabled);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
