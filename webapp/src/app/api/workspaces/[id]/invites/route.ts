import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { inviteSchema } from "@/lib/validation/schemas";
import { eq } from "drizzle-orm";
import { createInvite, listPendingInvites } from "@/lib/domain/invites";
import { sendInviteEmail } from "@/lib/email/send";
import { memberRow } from "@/lib/domain/members";
import { db } from "@/lib/db/client";
import { workspaces } from "@/lib/db/schema";

export const runtime = "nodejs";

/** Pending invites for the members screen. Requires AddMember. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireCapability(req, id, Capability.AddMember);
    return NextResponse.json({ invites: await listPendingInvites(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Invite a teammate by email (email-primary onboarding). Requires AddMember. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.AddMember);

    const rl = await limit(`invite:${hashId(ctx.sub)}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    const parsed = inviteSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    if (parsed.data.workspaceId !== id) return NextResponse.json({ error: "workspace_mismatch" }, { status: 400 });

    const invite = await createInvite({
      workspaceId: id,
      email: parsed.data.email,
      role: parsed.data.role,
      invitedBySub: ctx.sub,
      scopeChannelId: parsed.data.scopeChannelId ?? null,
    });

    const origin = new URL(req.url).origin;
    const link = `${origin}/join/${invite.token}`;
    const inviter = (await memberRow(id, ctx.sub))?.displayName ?? "A teammate";
    const [ws] = await db().select({ name: workspaces.name }).from(workspaces).where(eq(workspaces.id, id)).limit(1);
    const result = await sendInviteEmail({
      to: invite.email,
      workspaceName: ws?.name ?? "your workspace",
      inviterName: inviter,
      role: invite.role,
      link,
    });

    // suppressed: the recipient previously unsubscribed — the invite row exists but
    // we did NOT email them (compliance). Tell the admin so they can reach out another way.
    // When SMTP isn't configured (dev), return the link so the admin can share it manually.
    return NextResponse.json(
      {
        invited: invite.email,
        role: invite.role,
        emailSent: result.sent,
        suppressed: result.suppressed ?? false,
        link: result.sent ? undefined : link,
      },
      { status: 201 },
    );
  } catch (e) {
    return errorResponse(e);
  }
}
