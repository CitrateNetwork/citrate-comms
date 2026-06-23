import { NextResponse } from "next/server";
import { verifyUnsubscribeToken } from "@/lib/security/crypto";
import { suppress } from "@/lib/email/suppression";

/**
 * One-click unsubscribe endpoint (CAN-SPAM / CASL, RFC 8058). The token is an
 * HMAC-signed encoding of the email — no auth, no lookup, no trap. Honors the
 * unsubscribe immediately and permanently.
 *
 * - POST ?u=<token>      → RFC 8058 one-click (Gmail/Outlook native button) +
 *   the confirmation page's auto-submit. Returns 200.
 * - GET  ?u=<token>      → a client that follows the List-Unsubscribe https link
 *   directly. Suppresses, then 303s to the human confirmation page.
 * The token may also arrive as JSON { token } in a POST body.
 */
export const runtime = "nodejs";

async function tokenFrom(req: Request): Promise<string | null> {
  const q = new URL(req.url).searchParams.get("u");
  if (q) return q;
  try {
    const body = (await req.json()) as { token?: string };
    return body?.token ?? null;
  } catch {
    return null;
  }
}

async function doUnsubscribe(token: string | null): Promise<string | null> {
  if (!token) return null;
  const email = verifyUnsubscribeToken(token);
  if (!email) return null;
  await suppress(email, "unsubscribe-link");
  return email;
}

export async function POST(req: Request) {
  const email = await doUnsubscribe(await tokenFrom(req));
  if (!email) return NextResponse.json({ error: "invalid_token" }, { status: 400 });
  return NextResponse.json({ ok: true, email });
}

export async function GET(req: Request) {
  const origin = new URL(req.url).origin;
  const email = await doUnsubscribe(new URL(req.url).searchParams.get("u"));
  const dest = email ? `${origin}/unsubscribe?done=1` : `${origin}/unsubscribe?error=1`;
  return NextResponse.redirect(dest, { status: 303 });
}
