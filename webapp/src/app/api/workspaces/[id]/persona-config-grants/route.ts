import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { listConfigGrants, grantConfig } from "@/lib/domain/agent-config";

export const runtime = "nodejs";

/** CFG delegation: list config grants. Owner/Admin (ManageWorkspace). */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireCapability(req, id, Capability.ManageWorkspace);
    return NextResponse.json({ grants: await listConfigGrants(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Grant a member config rights over one persona (or all). Owner/Admin. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const body = (await readJson(req)) as { granteeSub?: unknown; personaId?: unknown };
    const granteeSub = typeof body.granteeSub === "string" ? body.granteeSub : "";
    if (!granteeSub) return NextResponse.json({ error: "missing_grantee" }, { status: 400 });
    const personaId = typeof body.personaId === "string" && body.personaId ? body.personaId : null;
    await grantConfig(id, granteeSub, personaId, ctx.sub);
    return NextResponse.json({ ok: true }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
