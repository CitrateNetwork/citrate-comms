import { NextResponse } from "next/server";
import { Capability, requireMember, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { createEventSchema } from "@/lib/validation/schemas";
import { createEvent, listEventsInRange } from "@/lib/domain/calendar";

export const runtime = "nodejs";

/** List the caller's events overlapping [from, to] (ISO). Any active member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const url = new URL(req.url);
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    if (!from || !to) return NextResponse.json({ error: "from and to (ISO) required" }, { status: 400 });
    const events = await listEventsInRange(ctx.workspaceId, ctx.sub, from, to);
    return NextResponse.json({ events });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Create an event. Requires CreateRecord (Member+). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = createEventSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    const { id: eventId } = await createEvent({ workspaceId: ctx.workspaceId, createdBySub: ctx.sub, ...parsed.data });
    return NextResponse.json({ id: eventId }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
