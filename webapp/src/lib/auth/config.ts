/**
 * Auth seam configuration. Client-safe values (NEXT_PUBLIC_*) live here; the
 * server reads its own secrets/claim names in `session.ts`.
 *
 * Ported from citrate-dataroom; configured for the `citrate-comms-web` client.
 */
import type { AuthMode } from "./types";

/**
 * Selected backend. The default is `oidc`, never `mock` — an unset
 * NEXT_PUBLIC_AUTH_MODE must fail closed, not open the forged-token dev gate.
 * Local dev sets NEXT_PUBLIC_AUTH_MODE=mock explicitly. Server enforcement is in
 * `session.ts` (resolveServerAuthMode).
 */
export const AUTH_MODE: AuthMode =
  (process.env.NEXT_PUBLIC_AUTH_MODE as AuthMode) || "oidc";

/** Public OIDC client config (Authorization Code + PKCE; public client, no secret). */
export const OIDC_PUBLIC = {
  issuer: process.env.NEXT_PUBLIC_OIDC_ISSUER || "",
  authorizeUrl: process.env.NEXT_PUBLIC_OIDC_AUTHORIZE_URL || "",
  tokenUrl: process.env.NEXT_PUBLIC_OIDC_TOKEN_URL || "",
  clientId: process.env.NEXT_PUBLIC_OIDC_CLIENT_ID || "citrate-comms-web",
  scope: process.env.NEXT_PUBLIC_OIDC_SCOPE || "openid profile wallet kyc offline_access",
  redirectPath: "/auth/callback",
} as const;

/** Claim names. The ID token's subject + wallet + email claims. */
export const CLAIM = {
  sub: process.env.NEXT_PUBLIC_AUTH_CLAIM_SUB || "sub",
  wallet: process.env.NEXT_PUBLIC_AUTH_CLAIM_WALLET || "wallet_address",
  email: process.env.NEXT_PUBLIC_AUTH_CLAIM_EMAIL || "email",
  emailVerified: "email_verified",
  entitlement: "https://citrate.ai/entitlement",
} as const;

/** Short-lived OAuth-flow cookies (PKCE verifier + anti-CSRF state). */
export const FLOW_COOKIE = {
  verifier: "cc_pkce_verifier",
  state: "cc_oauth_state",
  returnTo: "cc_return_to",
} as const;
