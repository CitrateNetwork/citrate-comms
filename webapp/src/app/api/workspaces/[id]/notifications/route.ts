import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { listNotifications, unreadCount, markRead } from "@/lib/domain/notifications";

export const runtime = "nodejs";

/** The caller's notifications + unread count (MEN-2). `?count=1` returns only the count. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const url = new URL(req.url);
    const unread = await unreadCount(id, ctx.sub);
    if (url.searchParams.get("count") === "1") return NextResponse.json({ unread });
    const items = await listNotifications(id, ctx.sub, 30);
    return NextResponse.json({ items, unread });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Mark notifications read: { all: true } or { ids: [...] }. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const body = (await readJson(req)) as { ids?: unknown; all?: unknown };
    const ids = Array.isArray(body.ids) ? body.ids.filter((x): x is string => typeof x === "string") : undefined;
    await markRead(id, ctx.sub, { ids, all: body.all === true });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
