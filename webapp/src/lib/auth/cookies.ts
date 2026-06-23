/**
 * Auth-cookie plumbing (ported from citrate-dataroom, FUA-EXPLORER-04). The OIDC
 * id/access tokens live in httpOnly cookies — never in web storage, never readable
 * by page script. Shared by the auth routes (set/clear) and verifySession (read
 * fallback when no Authorization header is present).
 *
 * Web-standard Request/Headers only (no next/server import) so every piece is
 * unit-testable in the node vitest environment.
 */

/** httpOnly cookie carrying the OIDC ID token (the app's session credential). */
export const ID_COOKIE = "cc_oidc_id";
/** httpOnly cookie carrying the authority access token (userinfo/logout). */
export const ACCESS_COOKIE = "cc_oidc_access";
/** httpOnly cookie carrying the rotating refresh token (silent re-auth in proxy.ts). */
export const REFRESH_COOKIE = "cc_oidc_refresh";
/** Refresh-token cookie lifetime — matches the authority's 14-day refresh TTL. */
export const REFRESH_MAX_AGE = 14 * 24 * 60 * 60;

/** Loose JWT shape check (three base64url segments, bounded size). For the ID token. */
export function looksLikeJwt(token: string): boolean {
  return token.length > 0 && token.length <= 8192 && /^[\w-]+\.[\w-]+\.[\w-]*$/.test(token);
}

/**
 * Sanity check for the ACCESS token, which is OPAQUE — auth.citrate.ai (panva
 * oidc-provider) issues opaque access tokens by default (a random bearer string,
 * NOT a JWT). It must therefore NOT be validated with {@link looksLikeJwt}; doing
 * so silently drops the access cookie. Accept any non-empty, bounded, header-safe
 * RFC 6750 b64token-shaped string.
 */
export function looksLikeOpaqueToken(token: string): boolean {
  return token.length > 0 && token.length <= 8192 && /^[A-Za-z0-9._~+/-]+=*$/.test(token);
}

/** Decode (NOT verify) a JWT payload. Verification stays in verifySession. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const payload = jwt.split(".")[1];
    if (!payload) return null;
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/** Read one cookie from a standard Request. */
export function cookieValue(req: Request, name: string): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1).trim()) || null;
      } catch {
        return part.slice(eq + 1).trim() || null;
      }
    }
  }
  return null;
}

/**
 * Serialize the httpOnly auth cookie. SameSite=Lax (NOT Strict): the session must
 * survive a top-level cross-site RETURN navigation from the authority/IdP back to
 * the app. `Lax` sends the cookie on top-level cross-site GET navigations (the
 * OIDC return pattern) while withholding it from cross-site POSTs/subresources —
 * the CSRF mitigation that matters. `Secure` outside dev.
 */
export function serializeAuthCookie(name: string, value: string, maxAge: number): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return (
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax` +
    `; Max-Age=${Math.max(0, Math.floor(maxAge))}${secure}`
  );
}

/** A short-lived, httpOnly flow cookie (PKCE verifier / state / returnTo). */
export function serializeFlowCookie(name: string, value: string, maxAgeSeconds = 600): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

/** Expire the cookie immediately (server-side logout / flow cleanup). */
export function clearAuthCookie(name: string): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
