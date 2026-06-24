import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { revokeConfig } from "@/lib/domain/agent-config";

export const runtime = "nodejs";

/** Revoke a config grant. Owner/Admin (ManageWorkspace). */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; grantId: string }> }) {
  try {
    const { id, grantId } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    await revokeConfig(id, grantId, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
