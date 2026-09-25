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
 *   directly. NO state change (scanners/prefetchers issue GETs) — 303s to the
 *   confirmation page, which POSTs the token (PBA-L3c-035).
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
  // PBA-L3c-035: a GET never changes state. Mail-security link scanners and prefetchers
  // follow List-Unsubscribe links, so a GET that suppressed would unsubscribe people who
  // never asked. Hand the token to the confirmation page, which POSTs it.
  const url = new URL(req.url);
  const token = url.searchParams.get("u");
  const dest = token ? `${url.origin}/unsubscribe?u=${encodeURIComponent(token)}` : `${url.origin}/unsubscribe?error=1`;
  return NextResponse.redirect(dest, { status: 303 });
}
