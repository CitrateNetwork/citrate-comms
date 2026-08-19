import { NextResponse } from "next/server";
import { Capability, requireChannel } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { channelWorkspace, isChannelMember, markChannelRead } from "@/lib/domain/channels";

export const runtime = "nodejs";

/**
 * Advance the caller's read cursor for a channel to `seq` (monotonic). Called by the
 * channel view when messages are seen, so the rail's unread badges clear. Requires
 * read access + channel membership.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.ReadChannel, channelWorkspace, isChannelMember);
    const body = (await readJson(req).catch(() => ({}))) as { seq?: unknown };
    const seq = Number(body?.seq);
    if (!Number.isFinite(seq) || seq < 0) return NextResponse.json({ error: "invalid seq" }, { status: 400 });
    await markChannelRead(ctx.workspaceId, id, ctx.sub, seq);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
