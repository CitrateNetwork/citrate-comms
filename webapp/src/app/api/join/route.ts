import { NextResponse } from "next/server";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { verifySession } from "@/lib/auth/session";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { acceptInvite } from "@/lib/domain/invites";
import { db } from "@/lib/db/client";
import { workspaces } from "@/lib/db/schema";

export const runtime = "nodejs";

const schema = z.object({ token: z.string().min(10).max(200) });

/**
 * Accept an invite. Binds the verified session identity to the workspace at the
 * granted role. The session's email (already email_verified-gated by verifySession)
 * must match the invite when present (defense in depth); wallet/passkey teammates
 * with no email claim are accepted on link possession alone.
 */
export async function POST(req: Request) {
  try {
    const session = await verifySession(req);
    if (!(session.authenticated && session.sub)) {
      return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
    }
    const parsed = schema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });

    const rl = await limit(`join:${hashId(session.sub)}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    const result = await acceptInvite({
      token: parsed.data.token,
      sub: session.sub,
      sessionEmail: session.email ?? null,
      walletAddress: session.walletAddress ?? null,
    });

    if (!result.ok) {
      // Only an invalid/expired/used token fails now.
      return NextResponse.json({ error: result.reason }, { status: 400 });
    }

    const [ws] = await db().select({ slug: workspaces.slug }).from(workspaces).where(eq(workspaces.id, result.workspaceId)).limit(1);
    return NextResponse.json({ ok: true, slug: ws?.slug, alreadyMember: result.alreadyMember });
  } catch (e) {
    return errorResponse(e);
  }
}
