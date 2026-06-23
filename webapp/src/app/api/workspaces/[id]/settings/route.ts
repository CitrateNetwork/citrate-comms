import { NextResponse } from "next/server";
import { Capability, requireCapability, requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { updateSettingsSchema } from "@/lib/validation/schemas";
import { getSettings, updateSettings } from "@/lib/domain/settings";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireMember(req, id);
    return NextResponse.json({ settings: await getSettings(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Update workspace settings (automation/notifications/appearance). Owner-only (ManageWorkspace). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = updateSettingsSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const settings = await updateSettings(id, parsed.data);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "settings_updated", target: Object.keys(parsed.data).join(",") });
    return NextResponse.json({ settings });
  } catch (e) {
    return errorResponse(e);
  }
}
