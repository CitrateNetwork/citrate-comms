import { NextResponse } from "next/server";
import {
  ID_COOKIE,
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  REFRESH_MAX_AGE,
  cookieValue,
  decodeJwtPayload,
  looksLikeJwt,
  looksLikeOpaqueToken,
  serializeAuthCookie,
  clearAuthCookie,
} from "@/lib/auth/cookies";
import { OIDC_PUBLIC, FLOW_COOKIE } from "@/lib/auth/config";

/**
 * OIDC Authorization Code + PKCE callback. Verifies the state cookie, exchanges the
 * code at the authority's token endpoint with the PKCE verifier, and sets the
 * httpOnly id/access cookies. The id token is decoded only to read sub/email here —
 * it is still VERIFIED by verifySession on every subsequent request. Member rows are
 * created lazily on first workspace action / invite-accept, so this route stays thin.
 */
export const runtime = "nodejs";

function tokenUrl(): string {
  const issuer = OIDC_PUBLIC.issuer.replace(/\/$/, "");
  return OIDC_PUBLIC.tokenUrl || `${issuer}/token`;
}

function fail(origin: string, reason: string) {
  const res = NextResponse.redirect(`${origin}/auth?error=${encodeURIComponent(reason)}`, { status: 303 });
  for (const c of Object.values(FLOW_COOKIE)) res.headers.append("set-cookie", clearAuthCookie(c));
  return res;
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const origin = url.origin;
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const expectedState = cookieValue(req, FLOW_COOKIE.state);
  const verifier = cookieValue(req, FLOW_COOKIE.verifier);
  const returnTo = cookieValue(req, FLOW_COOKIE.returnTo) || "/";
  if (!code || !state || !expectedState || state !== expectedState || !verifier) {
    return fail(origin, "invalid_state");
  }

  let idToken: string | undefined;
  let accessToken: string | undefined;
  let refreshToken: string | undefined;
  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${origin}${OIDC_PUBLIC.redirectPath}`,
      client_id: OIDC_PUBLIC.clientId,
      code_verifier: verifier,
    });
    const r = await fetch(tokenUrl(), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
      cache: "no-store",
    });
    if (!r.ok) return fail(origin, "token_exchange_failed");
    const j = (await r.json()) as { id_token?: string; access_token?: string; refresh_token?: string; scope?: string };
    idToken = j.id_token;
    accessToken = j.access_token;
    refreshToken = j.refresh_token;
  } catch {
    return fail(origin, "token_exchange_error");
  }

  if (!idToken || !looksLikeJwt(idToken)) return fail(origin, "no_id_token");
  const payload = decodeJwtPayload(idToken);
  if (!payload?.sub) return fail(origin, "no_subject");

  // returnTo is a same-origin path only (anti open-redirect).
  const safeReturn = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
  const res = NextResponse.redirect(`${origin}${safeReturn}`, { status: 303 });
  res.headers.append("set-cookie", serializeAuthCookie(ID_COOKIE, idToken, 60 * 60));
  // The access token is OPAQUE (panva default) — validate with looksLikeOpaqueToken,
  // NOT looksLikeJwt (which would silently drop it).
  if (accessToken && looksLikeOpaqueToken(accessToken)) {
    res.headers.append("set-cookie", serializeAuthCookie(ACCESS_COOKIE, accessToken, 60 * 60));
  }
  // Refresh token (offline_access) → 14-day cookie; proxy.ts uses it to silently
  // re-mint the 1-hour id_token so the session survives past an hour.
  if (refreshToken && looksLikeOpaqueToken(refreshToken)) {
    res.headers.append("set-cookie", serializeAuthCookie(REFRESH_COOKIE, refreshToken, REFRESH_MAX_AGE));
  }
  for (const c of Object.values(FLOW_COOKIE)) res.headers.append("set-cookie", clearAuthCookie(c));
  return res;
}
