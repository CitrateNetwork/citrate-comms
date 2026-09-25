import { NextResponse } from "next/server";
import { ID_COOKIE, ACCESS_COOKIE, REFRESH_COOKIE, clearAuthCookie, cookieValue } from "@/lib/auth/cookies";

/**
 * Clear the local session cookies and return to the sign-in screen.
 *
 * POST-ONLY by design. A GET logout is a well-known footgun: Next.js <Link>
 * prefetch, browser link-preloading, and link scanners all issue background GETs —
 * which would silently log the user out and bounce every subsequent navigation to
 * /auth. Sign-out is therefore a form POST (see AppShell). State-changing = POST.
 */
export const runtime = "nodejs";

/**
 * Best-effort RFC 7009 revocation of the refresh token at the authority (PBA-L3c-035):
 * clearing the cookie alone left a 14-day refresh token valid wherever it had been
 * copied. Bounded (3 s) and never blocks sign-out.
 */
async function revokeRefreshToken(token: string | null): Promise<void> {
  const issuer = (process.env.OIDC_ISSUER || process.env.NEXT_PUBLIC_OIDC_ISSUER || "").replace(/\/$/, "");
  if (!token || !issuer) return;
  const endpoint = process.env.OIDC_REVOCATION_URL || `${issuer}/token/revocation`;
  const clientId = process.env.NEXT_PUBLIC_OIDC_CLIENT_ID || "citrate-comms-web";
  try {
    await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token, token_type_hint: "refresh_token", client_id: clientId }),
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    /* best-effort: the cookies are cleared regardless */
  }
}

export async function POST(req: Request) {
  await revokeRefreshToken(cookieValue(req, REFRESH_COOKIE));
  const origin = new URL(req.url).origin;
  const res = NextResponse.redirect(`${origin}/auth`, { status: 303 });
  res.headers.append("set-cookie", clearAuthCookie(ID_COOKIE));
  res.headers.append("set-cookie", clearAuthCookie(ACCESS_COOKIE));
  res.headers.append("set-cookie", clearAuthCookie(REFRESH_COOKIE));
  return res;
}
