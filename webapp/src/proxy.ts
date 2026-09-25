/**
 * Request gate (Next 16 proxy — middleware successor). Three jobs, in order:
 *
 *  A. CSRF (PBA-L3c-026): a state-changing /api call that rides the session cookie must
 *     be same-origin (Sec-Fetch-Site / Origin) — else 403 before any handler runs.
 *  B. CSP (PBA-L3c-008): a fresh nonce per request; the nonce'd CSP is set on the
 *     FORWARDED request headers (Next stamps the nonce onto its own <script> tags during
 *     SSR) and mirrored onto the response so the browser enforces it.
 *  C. Silent token refresh (below).
 *
 * Silent token refresh:
 *
 * The authority's id_token lives ~1 hour. Without refresh, every server-rendered
 * page and API call starts failing auth after an hour and bounces to /auth. This
 * proxy fixes that: when the id_token is missing or about to expire AND a refresh
 * token is present, it calls the token endpoint, then
 *   1. FORWARDS the new id_token onto the request headers so the CURRENT request's
 *      page/route sees a valid session (no one-request bounce), and
 *   2. SETS the rotated cookies on the response so the browser updates.
 * Any failure passes through untouched — verifySession remains the hard gate.
 *
 * Runs on app + API routes (not static assets, not prefetches, not the auth flow).
 */
import { NextResponse, type NextRequest } from "next/server";
import { ID_COOKIE, ACCESS_COOKIE, REFRESH_COOKIE, REFRESH_MAX_AGE, serializeAuthCookie } from "@/lib/auth/cookies";
import { buildCsp, newNonce } from "@/lib/security/csp";
import { isForgedMutation } from "@/lib/security/csrf";

const ID_TTL = 60 * 60; // 1h, matches the authority's id_token TTL
const REFRESH_SKEW_MS = 120_000; // refresh when within 2 min of expiry

/** Read a JWT's `exp` (ms) without verifying — verification stays in verifySession. */
function jwtExpMs(jwt?: string): number | null {
  if (!jwt) return null;
  const seg = jwt.split(".")[1];
  if (!seg) return null;
  try {
    const json = JSON.parse(atob(seg.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof json.exp === "number" ? json.exp * 1000 : null;
  } catch {
    return null;
  }
}

/** Paths that own their cookies (auth flow) or are public — never token-refreshed here. */
const NO_REFRESH = /^\/(?:auth\/(?:callback|start|logout)|unsubscribe|api\/unsubscribe)(?:\/|$|\?)/;

export default async function proxy(request: NextRequest): Promise<NextResponse> {
  const { pathname } = request.nextUrl;

  // A. CSRF — refuse a cross-site, cookie-authenticated mutation outright.
  const hasSession = Boolean(request.cookies.get(ID_COOKIE)?.value || request.cookies.get(REFRESH_COOKIE)?.value);
  if (isForgedMutation(request, pathname, hasSession)) {
    return NextResponse.json({ error: "cross-origin request refused" }, { status: 403 });
  }

  // B. CSP — per-request nonce on the forwarded request + the response.
  const nonce = newNonce();
  const csp = buildCsp(nonce);
  const baseHeaders = new Headers(request.headers);
  baseHeaders.set("x-nonce", nonce);
  baseHeaders.set("content-security-policy", csp);
  const withCsp = (res: NextResponse) => {
    res.headers.set("content-security-policy", csp);
    return res;
  };
  const pass = () => withCsp(NextResponse.next({ request: { headers: baseHeaders } }));

  // C. Silent refresh.
  if (NO_REFRESH.test(pathname)) return pass();
  const refresh = request.cookies.get(REFRESH_COOKIE)?.value;
  if (!refresh) return pass(); // can't refresh; verifySession will gate

  const id = request.cookies.get(ID_COOKIE)?.value;
  const expMs = jwtExpMs(id);
  const needsRefresh = !id || expMs === null || expMs - Date.now() < REFRESH_SKEW_MS;
  if (!needsRefresh) return pass();

  const issuer = (process.env.OIDC_ISSUER || process.env.NEXT_PUBLIC_OIDC_ISSUER || "").replace(/\/$/, "");
  const clientId = process.env.NEXT_PUBLIC_OIDC_CLIENT_ID || "citrate-comms-web";
  if (!issuer) return pass();

  try {
    const r = await fetch(`${issuer}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId }),
      cache: "no-store",
    });
    if (!r.ok) return pass();
    const j = (await r.json()) as { id_token?: string; access_token?: string; refresh_token?: string };
    if (!j.id_token) return pass();

    // Forward the new id_token onto THIS request so the page/route sees a fresh session.
    const jar = new Map<string, string>();
    for (const c of request.cookies.getAll()) jar.set(c.name, c.value);
    jar.set(ID_COOKIE, j.id_token);
    if (j.refresh_token) jar.set(REFRESH_COOKIE, j.refresh_token);
    if (j.access_token) jar.set(ACCESS_COOKIE, j.access_token);
    const requestHeaders = new Headers(baseHeaders);
    requestHeaders.set(
      "cookie",
      Array.from(jar.entries())
        .map(([k, v]) => `${k}=${v}`)
        .join("; "),
    );

    const response = withCsp(NextResponse.next({ request: { headers: requestHeaders } }));
    response.headers.append("set-cookie", serializeAuthCookie(ID_COOKIE, j.id_token, ID_TTL));
    if (j.refresh_token) response.headers.append("set-cookie", serializeAuthCookie(REFRESH_COOKIE, j.refresh_token, REFRESH_MAX_AGE));
    if (j.access_token) response.headers.append("set-cookie", serializeAuthCookie(ACCESS_COOKIE, j.access_token, ID_TTL));
    return response;
  } catch {
    return pass();
  }
}

export const config = {
  matcher: [
    {
      // Every app + API request except static assets. The auth-flow routes and the public
      // unsubscribe surface get CSP + CSRF but skip token refresh (NO_REFRESH above).
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
