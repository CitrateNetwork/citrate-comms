import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { batchInviteSchema } from "@/lib/validation/schemas";
import { canGrant, type Role } from "@/lib/rbac/matrix";
import { createInvite } from "@/lib/domain/invites";
import { sendInviteEmail } from "@/lib/email/send";
import { memberRow } from "@/lib/domain/members";
import { db } from "@/lib/db/client";
import { workspaces } from "@/lib/db/schema";

export const runtime = "nodejs";

interface BatchResult {
  email: string;
  emailSent: boolean;
  suppressed: boolean;
  link?: string; // returned only when SMTP isn't configured (dev) so the admin can share
}

/**
 * Invite many teammates at once (Members screen batch). One rate-limit check per batch
 * (the batch is one admin action). Anti-escalation: the inviter must be entitled to grant
 * the chosen role. De-dupes + lowercases emails. Returns a per-email result so the UI can
 * show which sent / were suppressed / need a manual link.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.AddMember);

    const parsed = batchInviteSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    if (parsed.data.workspaceId !== id) return NextResponse.json({ error: "workspace_mismatch" }, { status: 400 });
    if (!canGrant(ctx.role, parsed.data.role as Role)) {
      return NextResponse.json({ error: "forbidden_role" }, { status: 403 });
    }

    const rl = await limit(`invite-batch:${hashId(ctx.sub)}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    // De-dupe + normalize.
    const emails = Array.from(new Set(parsed.data.emails.map((e) => e.trim().toLowerCase()))).filter(Boolean);

    const origin = new URL(req.url).origin;
    const inviter = (await memberRow(id, ctx.sub))?.displayName ?? "A teammate";
    const [ws] = await db().select({ name: workspaces.name }).from(workspaces).where(eq(workspaces.id, id)).limit(1);
    const workspaceName = ws?.name ?? "your workspace";

    const results: BatchResult[] = [];
    for (const email of emails) {
      try {
        const invite = await createInvite({
          workspaceId: id,
          email,
          role: parsed.data.role as Role,
          invitedBySub: ctx.sub,
          scopeChannelId: parsed.data.scopeChannelId ?? null,
        });
        const link = `${origin}/join/${invite.token}`;
        const sent = await sendInviteEmail({ to: email, workspaceName, inviterName: inviter, role: invite.role, link });
        results.push({ email, emailSent: sent.sent, suppressed: sent.suppressed ?? false, link: sent.sent ? undefined : link });
      } catch {
        results.push({ email, emailSent: false, suppressed: false });
      }
    }

    return NextResponse.json(
      {
        count: results.length,
        sent: results.filter((r) => r.emailSent).length,
        suppressed: results.filter((r) => r.suppressed).length,
        results,
      },
      { status: 201 },
    );
  } catch (e) {
    return errorResponse(e);
  }
}
