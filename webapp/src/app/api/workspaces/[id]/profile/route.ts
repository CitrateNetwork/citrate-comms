import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { updateProfileSchema } from "@/lib/validation/schemas";
import { updateDisplayName, setMemberTimezone } from "@/lib/domain/settings";

export const runtime = "nodejs";

/** Update the caller's own profile (display name and/or browser timezone). Any active member. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const parsed = updateProfileSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    if (parsed.data.displayName !== undefined) await updateDisplayName(id, ctx.sub, parsed.data.displayName);
    if (parsed.data.timezone !== undefined) await setMemberTimezone(id, ctx.sub, parsed.data.timezone);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
