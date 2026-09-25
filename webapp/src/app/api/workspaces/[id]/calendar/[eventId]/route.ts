import { NextResponse } from "next/server";
import { Capability, requireMember, requireCapability, type MemberCtx } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { updateEventSchema } from "@/lib/validation/schemas";
import { cancelEvent, getEvent, updateEvent, canSeeEvent, canEditEvent, type CalendarEvent } from "@/lib/domain/calendar";

export const runtime = "nodejs";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The event, only if `ctx` may SEE it (creator, attendee, or Owner/Admin); else null. */
async function visibleEvent(ctx: MemberCtx, eventId: string): Promise<CalendarEvent | null> {
  if (!UUID_RE.test(eventId)) return null;
  const event = await getEvent(ctx.workspaceId, eventId);
  return event && canSeeEvent(event, ctx.sub, ctx.role) ? event : null;
}

/**
 * Fetch one event (with attendees). PBA-L3c-007: only its creator, its attendees, and
 * Owner/Admin — everyone else gets 404 (the list endpoint is attendee-scoped the same
 * way, so the item route no longer leaks what the list hides).
 */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireMember(req, id);
    const event = await visibleEvent(ctx, eventId);
    if (!event) return NextResponse.json({ error: "not_found" }, { status: 404 });
    return NextResponse.json({ event });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Gate a write: 404 if the caller can't see the event, 403 unless organizer/admin;
 *  null when the write may proceed. */
async function denyEdit(ctx: MemberCtx, eventId: string): Promise<NextResponse | null> {
  const event = await visibleEvent(ctx, eventId);
  if (!event) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (!canEditEvent(event, ctx.sub, ctx.role)) return NextResponse.json({ error: "only the organizer or an admin can change this event" }, { status: 403 });
  return null;
}

/** Update an event. CreateRecord AND (organizer or Owner/Admin) — PBA-L3c-007. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = updateEventSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    const denied = await denyEdit(ctx, eventId);
    if (denied) return denied;
    await updateEvent(ctx.workspaceId, eventId, parsed.data);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Cancel an event (soft). CreateRecord AND (organizer or Owner/Admin) — PBA-L3c-007. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; eventId: string }> }) {
  try {
    const { id, eventId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const denied = await denyEdit(ctx, eventId);
    if (denied) return denied;
    await cancelEvent(ctx.workspaceId, eventId, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
