import { NextResponse } from "next/server";
import { Capability, requireChannel } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { channelWorkspace, isChannelMember } from "@/lib/domain/channels";
import { respondInChannelAsAgent } from "@/lib/domain/channel-agent";

export const runtime = "nodejs";
export const maxDuration = 300;

/**
 * MEN-1 — call an @-mentioned agent into this channel. The invoking human must be a channel
 * member able to post; the agent then reads the recent channel context through its persona and
 * posts one read-only reply as itself. Rate-limited (inference costs) and audited.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.PostMessage, channelWorkspace, isChannelMember);

    const rl = await limit(`agent-ping:${hashId(ctx.sub)}:${id}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    const body = (await readJson(req)) as { agentSub?: unknown };
    const agentSub = typeof body.agentSub === "string" ? body.agentSub : "";
    if (!agentSub) return NextResponse.json({ error: "missing_agent" }, { status: 400 });

    const result = await respondInChannelAsAgent({
      workspaceId: ctx.workspaceId,
      channelId: id,
      agentMemberSub: agentSub,
      invokedBySub: ctx.sub,
      invokerRole: ctx.role,
    });
    if (!result.ok) return NextResponse.json({ error: result.reason ?? "failed" }, { status: 422 });

    // The new agent message is picked up by the channel poll; return it for instant render.
    return NextResponse.json({ ok: true, messageId: result.messageId }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
