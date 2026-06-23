import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { personaPromptSchema } from "@/lib/validation/schemas";
import { setPromptLayer } from "@/lib/domain/personas";

export const runtime = "nodejs";

/** Set (or clear, when content is blank) an editable prompt layer 1–4. Owner/Admin. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = personaPromptSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setPromptLayer(id, personaId, parsed.data.layer, parsed.data.content, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
