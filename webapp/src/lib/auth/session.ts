/**
 * Server-side session verification — the server half of the auth seam. Ported
 * from citrate-dataroom (WEB-1 fail-closed mode resolution + FUA-EXPLORER-01
 * mandatory issuer/audience), extended for citrate-comms:
 *  - FWA-C6-01: an `email` claim is trusted ONLY when `email_verified === true`.
 *  - the `https://citrate.ai/entitlement` claim is surfaced (gates workspace entry).
 *
 * `verifySession(req)` is the ONLY identity check API routes + guards call. It
 * returns a normalized AuthSession regardless of issuer:
 *  - `oidc`  — verify a Citrate-issued JWT against auth.citrate.ai's JWKS (jose),
 *    enforcing issuer + audience, then read the sub/wallet/email/entitlement claims.
 *  - `mock`  — dev only: unsigned mock token / dev header. Disabled in prod unless
 *    ALLOW_MOCK_AUTH=1.
 */
import { createRemoteJWKSet, jwtVerify } from "jose";
import { ID_COOKIE, cookieValue } from "./cookies";
import { CLAIM } from "./config";
import type { AuthSession, Entitlement } from "./types";

/**
 * WEB-1: fail-closed server mode resolution. Unset/unknown → `oidc` (rejects
 * everything until a JWKS is configured); `mock` in production is disabled unless
 * ALLOW_MOCK_AUTH=1. Exported for direct unit testing of the matrix.
 */
export type ServerAuthMode = "oidc" | "mock" | "mock-disabled";
export function resolveServerAuthMode(
  env: Record<string, string | undefined> = process.env,
): ServerAuthMode {
  const requested = env.NEXT_PUBLIC_AUTH_MODE;
  if (requested === "oidc") return "oidc";
  if (requested === "mock") {
    if (env.NODE_ENV === "production" && env.ALLOW_MOCK_AUTH !== "1") return "mock-disabled";
    return "mock";
  }
  return "oidc"; // unset/unknown ⇒ fail closed onto the verifying path
}

const claimSub = () =>
  process.env.AUTH_CLAIM_SUB || process.env.NEXT_PUBLIC_AUTH_CLAIM_SUB || "sub";
const claimWallet = () =>
  process.env.AUTH_CLAIM_WALLET || process.env.NEXT_PUBLIC_AUTH_CLAIM_WALLET || "wallet_address";

/**
 * FWA-C6-01: read an email claim ONLY if `email_verified === true` (accept the
 * legacy string "true" too). An unverified email is dropped — never trust it for
 * identity, account-link, or invite-matching. This mirrors the tripwire the
 * authority enforces on its own federation paths.
 */
function trustedEmail(payload: Record<string, unknown>): { email?: string; verified: boolean } {
  const raw = payload[CLAIM.email];
  const ev = payload[CLAIM.emailVerified];
  const verified = ev === true || ev === "true";
  if (typeof raw === "string" && raw.length > 0 && verified) return { email: raw.toLowerCase(), verified: true };
  return { verified: Boolean(verified) };
}

function readEntitlement(payload: Record<string, unknown>): Entitlement | undefined {
  const e = payload[CLAIM.entitlement];
  if (e && typeof e === "object") return e as Entitlement;
  return undefined;
}

/** The caller's credential: the Authorization Bearer header, else the httpOnly cookie. */
export function tokenFromRequest(req: Request): string | null {
  const header = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (header) return header;
  return cookieValue(req, ID_COOKIE);
}

// --- OIDC (real authority) --------------------------------------------------

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
function jwkSet() {
  const url = process.env.OIDC_JWKS_URL;
  if (!url) throw new Error("OIDC_JWKS_URL is not set");
  if (!jwks) jwks = createRemoteJWKSet(new URL(url));
  return jwks;
}

let warnedOidcConfig = false;

/**
 * FUA-EXPLORER-01: issuer + audience MUST both be set and enforced, or every token
 * is rejected (fail closed). auth.citrate.ai is a SHARED authority across RPs; a
 * token minted for a different relying party must never be accepted here.
 * `OIDC_AUDIENCE` must equal this client's id (`citrate-comms-web`).
 */
function requiredOidcConfig(): { issuer: string; audience: string } | null {
  const issuer = process.env.OIDC_ISSUER;
  const audience = process.env.OIDC_AUDIENCE;
  if (!issuer || !audience) return null;
  return { issuer, audience };
}

/**
 * Verify an id_token string. The single OIDC verification path — used by both
 * `verifySession(req)` (API routes, token from the real request) and
 * `serverSession()` (RSC/pages, token from `cookies()`).
 */
export async function verifyOidcToken(token: string | null): Promise<AuthSession> {
  if (!token) return { required: true, authenticated: false };
  const cfg = requiredOidcConfig();
  if (!cfg) {
    if (!warnedOidcConfig) {
      warnedOidcConfig = true;
      console.error(
        "[auth] OIDC_ISSUER and OIDC_AUDIENCE must both be set in oidc mode; " +
          "refusing all tokens until configured (fail closed, FUA-EXPLORER-01).",
      );
    }
    return { required: true, authenticated: false };
  }
  try {
    const { payload } = await jwtVerify(token, jwkSet(), { issuer: cfg.issuer, audience: cfg.audience });
    const sub = payload[claimSub()] as string | undefined;
    const walletAddress = (payload[claimWallet()] as string | undefined)?.toLowerCase();
    const { email, verified } = trustedEmail(payload as Record<string, unknown>);
    return {
      required: true,
      authenticated: Boolean(sub),
      sub,
      walletAddress,
      email,
      emailVerified: verified,
      entitlement: readEntitlement(payload as Record<string, unknown>),
    };
  } catch {
    return { required: true, authenticated: false };
  }
}

async function verifyOidc(req: Request): Promise<AuthSession> {
  return verifyOidcToken(tokenFromRequest(req));
}

// --- Mock issuer (dev only) -------------------------------------------------

export function verifyMockToken(token: string | null, devAddr: string | null): AuthSession {
  if (token) {
    try {
      const json = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as Record<string, unknown>;
      const sub = (json[claimSub()] ?? json.sub) as string | undefined;
      const walletAddress = ((json[claimWallet()] ?? json.wallet_address) as string | undefined)?.toLowerCase();
      const { email, verified } = trustedEmail(json);
      if (sub || walletAddress) {
        return { required: false, authenticated: true, sub, walletAddress, email, emailVerified: verified };
      }
    } catch {
      /* fall through to header */
    }
  }
  if (devAddr) {
    return { required: false, authenticated: true, sub: `dev:${devAddr}`, walletAddress: devAddr };
  }
  return { required: false, authenticated: false };
}

function verifyMock(req: Request): AuthSession {
  return verifyMockToken(tokenFromRequest(req), req.headers.get("x-citrate-dev-address")?.toLowerCase() ?? null);
}

let warnedMockDisabled = false;

export async function verifySession(req: Request): Promise<AuthSession> {
  const mode = resolveServerAuthMode();
  if (mode === "oidc") return verifyOidc(req);
  if (mode === "mock-disabled") {
    if (!warnedMockDisabled) {
      warnedMockDisabled = true;
      console.error(
        "[auth] NEXT_PUBLIC_AUTH_MODE=mock is DISABLED in production (forged-token " +
          "risk, WEB-1). All requests unauthenticated. Set NEXT_PUBLIC_AUTH_MODE=oidc.",
      );
    }
    return { required: true, authenticated: false };
  }
  return verifyMock(req);
}

/**
 * The canonical owner key for all per-user data: the stable OIDC `subject`, NOT
 * the wallet address. Returned VERBATIM — `sub` is a case-sensitive opaque id.
 */
export function sessionOwner(s: AuthSession): string | null {
  return s.sub ?? null;
}

/** Resolve the owner for a request in one call. Null when unauthenticated. */
export async function requireOwner(req: Request): Promise<string | null> {
  const auth = await verifySession(req);
  if (auth.required && !auth.authenticated) return null;
  return sessionOwner(auth);
}
