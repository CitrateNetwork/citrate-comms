import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { createChannelSchema } from "@/lib/validation/schemas";
import { createChannel } from "@/lib/domain/channels";

export const runtime = "nodejs";

/** Create a channel/forum/dm in a workspace. Requires CreateChannel. */
export async function POST(req: Request) {
  try {
    const body = await readJson(req);
    const parsed = createChannelSchema.safeParse(body);
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });

    // DMs/group DMs are open to Members + Partners; full channels/forums stay Owner/Admin.
    const requiredCap = parsed.data.kind === "dm" ? Capability.CreateDirectMessage : Capability.CreateChannel;
    const ctx = await requireCapability(req, parsed.data.workspaceId, requiredCap);

    const rl = await limit(`create-channel:${hashId(ctx.sub)}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    const channel = await createChannel({
      workspaceId: parsed.data.workspaceId,
      kind: parsed.data.kind,
      name: parsed.data.name,
      topic: parsed.data.topic ?? null,
      createdBySub: ctx.sub,
      memberSubs: parsed.data.memberSubs,
    });
    return NextResponse.json({ channel }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
