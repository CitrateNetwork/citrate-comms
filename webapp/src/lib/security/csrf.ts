/**
 * Cross-site request-forgery guard for cookie-authenticated mutations (PBA-L3c-026).
 * Ported from citrate-dataroom (DR-B-011).
 *
 * The auth cookies are `SameSite=Lax`, which blocks the classic cross-site POST — but that
 * was the ONLY control, and it degrades if a same-site sibling subdomain is ever hostile,
 * and `readJson` parses a `text/plain` (CORS-simple) body. This adds an explicit
 * same-origin assertion, enforced centrally in src/proxy.ts for every non-safe /api call
 * that rides the session cookie.
 *
 * `Sec-Fetch-Site` is sent by every modern browser and cannot be set by page script, so
 * it is the primary signal; `Origin` vs `Host` is the fallback. A request with neither is
 * a non-browser client (curl / server-to-server).
 */
export function isSameOrigin(req: Request): boolean {
  const site = req.headers.get("sec-fetch-site");
  if (site) {
    // "same-origin" = our own fetch/form; "none" = user-initiated (address bar).
    // "cross-site" and "same-site" (a sibling subdomain) may not mutate.
    return site === "same-origin" || site === "none";
  }
  const origin = req.headers.get("origin");
  if (origin) {
    const host = req.headers.get("x-forwarded-host") || req.headers.get("host");
    if (!host) return false;
    try {
      return new URL(origin).host === host;
    } catch {
      return false;
    }
  }
  return true;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Should this request be refused as a cross-site forgery? Only state-changing API calls
 * that carry the ambient session cookie (and no explicit Authorization bearer) are
 * checked — a bearer token or a cookie-less call (cron, mail one-click unsubscribe, Blob
 * callbacks) is not a forgeable browser credential.
 */
export function isForgedMutation(req: Request, pathname: string, hasSessionCookie: boolean): boolean {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return false;
  if (!pathname.startsWith("/api/")) return false;
  if (!hasSessionCookie) return false;
  if (req.headers.get("authorization")) return false;
  return !isSameOrigin(req);
}

/**
 * PBA-L3c-026 (content-type half): a cookie-authenticated, bearer-less, state-changing
 * /api call that carries a body must declare JSON or multipart (file upload). A
 * CORS-simple `text/plain` / `application/x-www-form-urlencoded` body — the shape a
 * cross-site form can submit without a preflight — is refused with 415. Body-less calls
 * (no content-type, content-length 0/absent) pass.
 */
export function isUnsafeBodyType(req: Request, pathname: string, hasSessionCookie: boolean): boolean {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return false;
  if (!pathname.startsWith("/api/")) return false;
  if (!hasSessionCookie || req.headers.get("authorization")) return false;
  const ct = (req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (!ct) {
    const len = req.headers.get("content-length");
    return len !== null && len !== "0";
  }
  if (ct === "application/json" || (ct.startsWith("application/") && ct.endsWith("+json"))) return false;
  if (ct === "multipart/form-data") return false;
  return true;
}
