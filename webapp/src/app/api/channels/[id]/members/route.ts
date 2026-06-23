import { NextResponse } from "next/server";
import { z } from "zod";
import { Capability, requireChannel } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { channelWorkspace, isChannelMember, addChannelMembers, setChannelHasAgent } from "@/lib/domain/channels";
import { memberRow } from "@/lib/domain/members";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

const addSchema = z.object({ sub: z.string().min(1) });

/**
 * Seat a workspace member (human or agent) into a channel. Requires AddMember on the
 * channel. Seating an agent flips the channel's AGENT badge and audits AgentAdded.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.AddMember, channelWorkspace, isChannelMember);
    const parsed = addSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });

    const target = await memberRow(ctx.workspaceId, parsed.data.sub);
    if (!target || target.status !== "active") return NextResponse.json({ error: "not_a_member" }, { status: 404 });

    await addChannelMembers(ctx.workspaceId, id, [parsed.data.sub]);
    if (target.isAgent) await setChannelHasAgent(ctx.workspaceId, id, true);

    await appendAudit({
      workspaceId: ctx.workspaceId,
      actorSub: ctx.sub,
      event: target.isAgent ? "agent_added_to_channel" : "member_added_to_channel",
      target: `${id}:${parsed.data.sub}`,
    });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
