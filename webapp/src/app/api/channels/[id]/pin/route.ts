import { NextResponse } from "next/server";
import { z } from "zod";
import { Capability, requireChannel } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { channelWorkspace, isChannelMember } from "@/lib/domain/channels";
import { setMessagePinned, listPinnedMessages } from "@/lib/domain/messages";

export const runtime = "nodejs";

const pinSchema = z.object({ messageId: z.string().uuid(), pinned: z.boolean() });

/** Pinned messages for the channel header. Any channel member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.ReadChannel, channelWorkspace, isChannelMember);
    return NextResponse.json({ pinned: await listPinnedMessages(ctx.workspaceId, id) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Pin or unpin a message. Requires PostMessage + channel membership. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.PostMessage, channelWorkspace, isChannelMember);
    const parsed = pinSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setMessagePinned(ctx.workspaceId, id, parsed.data.messageId, parsed.data.pinned);
    return NextResponse.json({ pinned: await listPinnedMessages(ctx.workspaceId, id) });
  } catch (e) {
    return errorResponse(e);
  }
}
