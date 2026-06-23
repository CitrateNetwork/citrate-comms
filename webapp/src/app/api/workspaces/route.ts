import { NextResponse } from "next/server";
import { verifySession, sessionOwner } from "@/lib/auth/session";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { createWorkspaceSchema } from "@/lib/validation/schemas";
import { createWorkspace, workspacesForUser } from "@/lib/domain/workspaces";

export const runtime = "nodejs";

/** List the caller's workspaces. */
export async function GET(req: Request) {
  const session = await verifySession(req);
  const sub = sessionOwner(session);
  if (!sub) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  return NextResponse.json({ workspaces: await workspacesForUser(sub) });
}

/** Create a workspace; the caller becomes Owner. */
export async function POST(req: Request) {
  const session = await verifySession(req);
  const sub = sessionOwner(session);
  if (!sub) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });

  const rl = await limit(`create-ws:${hashId(sub)}`);
  if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "bad_json" }, { status: 400 });
  }
  const parsed = createWorkspaceSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });

  const ws = await createWorkspace({
    name: parsed.data.name,
    ownerSub: sub,
    ownerWallet: session.walletAddress ?? null,
    ownerEmail: session.email ?? null, // already email_verified-gated in verifySession
  });
  return NextResponse.json({ workspace: ws }, { status: 201 });
}
