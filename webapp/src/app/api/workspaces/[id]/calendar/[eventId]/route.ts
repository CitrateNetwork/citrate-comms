import { NextResponse } from "next/server";
import { Capability, requireMember, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { updateEventSchema } from "@/lib/validation/schemas";
import { cancelEvent, getEvent, updateEvent } from "@/lib/domain/calendar";

export const runtime = "nodejs";

/** Fetch one event (with attendees). Any active member of the workspace. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireMember(req, id);
    const event = await getEvent(ctx.workspaceId, eventId);
    if (!event) return NextResponse.json({ error: "not_found" }, { status: 404 });
    return NextResponse.json({ event });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Update an event. Requires CreateRecord (Member+). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = updateEventSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    await updateEvent(ctx.workspaceId, eventId, parsed.data);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Cancel an event (soft). Requires CreateRecord (Member+). */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    await cancelEvent(ctx.workspaceId, eventId, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
