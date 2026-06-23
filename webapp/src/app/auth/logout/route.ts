import { NextResponse } from "next/server";
import { ID_COOKIE, ACCESS_COOKIE, REFRESH_COOKIE, clearAuthCookie } from "@/lib/auth/cookies";

/**
 * Clear the local session cookies and return to the sign-in screen.
 *
 * POST-ONLY by design. A GET logout is a well-known footgun: Next.js <Link>
 * prefetch, browser link-preloading, and link scanners all issue background GETs —
 * which would silently log the user out and bounce every subsequent navigation to
 * /auth. Sign-out is therefore a form POST (see AppShell). State-changing = POST.
 */
export const runtime = "nodejs";

export async function POST(req: Request) {
  const origin = new URL(req.url).origin;
  const res = NextResponse.redirect(`${origin}/auth`, { status: 303 });
  res.headers.append("set-cookie", clearAuthCookie(ID_COOKIE));
  res.headers.append("set-cookie", clearAuthCookie(ACCESS_COOKIE));
  res.headers.append("set-cookie", clearAuthCookie(REFRESH_COOKIE));
  return res;
}
