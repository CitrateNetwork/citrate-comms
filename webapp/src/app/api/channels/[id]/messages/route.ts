import { NextResponse } from "next/server";
import { Capability, requireChannel } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { sendMessageSchema } from "@/lib/validation/schemas";
import { listMessages, sendMessage, linkMessageAttachments, getMessageAttachments } from "@/lib/domain/messages";
import { channelWorkspace, isChannelMember } from "@/lib/domain/channels";
import { notifyChannelMentions } from "@/lib/domain/notifications";

export const runtime = "nodejs";

/** List messages in a channel. `?after=<seq>` returns only newer rows (poll cursor). */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.ReadChannel, channelWorkspace, isChannelMember);
    const after = new URL(req.url).searchParams.get("after");
    const afterSeq = after != null && after !== "" ? Number(after) : undefined;
    const messages = await listMessages(ctx.workspaceId, id, {
      afterSeq: Number.isFinite(afterSeq) ? afterSeq : undefined,
    });
    return NextResponse.json({ messages });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Send a message to a channel. Requires PostMessage + channel membership. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.PostMessage, channelWorkspace, isChannelMember);

    const rl = await limit(`send:${hashId(ctx.sub)}:${id}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    const parsed = sendMessageSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    const attachmentIds = parsed.data.attachmentIds ?? [];
    if (!parsed.data.body && attachmentIds.length === 0) return NextResponse.json({ error: "empty" }, { status: 400 });

    const message = await sendMessage({
      workspaceId: ctx.workspaceId,
      channelId: id,
      authorSub: ctx.sub,
      body: parsed.data.body || (attachmentIds.length ? "" : parsed.data.body),
      fromAgent: ctx.isAgent,
      threadId: parsed.data.threadId ?? null,
      parentId: parsed.data.parentId ?? null,
      clientMsgId: parsed.data.clientMsgId ?? null,
    });
    if (attachmentIds.length) {
      await linkMessageAttachments(ctx.workspaceId, message.id, attachmentIds);
      message.attachments = await getMessageAttachments(ctx.workspaceId, message.id);
    }
    // MEN-2: ping any @-mentioned members (best-effort; never blocks the send).
    if (parsed.data.body) {
      await notifyChannelMentions({ workspaceId: ctx.workspaceId, channelId: id, messageId: message.id, body: parsed.data.body, actorSub: ctx.sub });
    }
    return NextResponse.json({ message }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
