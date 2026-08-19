import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { rsvpSchema } from "@/lib/validation/schemas";
import { setAttendeeResponse } from "@/lib/domain/calendar";

export const runtime = "nodejs";

/** Set the caller's RSVP on an event they're invited to. Any active member. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireMember(req, id);
    const parsed = rsvpSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setAttendeeResponse(ctx.workspaceId, eventId, ctx.sub, parsed.data.response);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
