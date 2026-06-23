/**
 * Auth seam — provider-agnostic identity contract. The web app is a GENERIC OIDC
 * relying party behind this seam: the rest of the app depends only on these types,
 * `useAuth()` (client) and `verifySession()` (server). The concrete backend — mock
 * issuer (dev) or the Citrate authority (auth.citrate.ai) via Authorization Code +
 * PKCE (prod) — is swappable with zero changes outside src/lib/auth/.
 *
 * Ported from citrate-dataroom/citrate-explorer. Extended for citrate-comms with
 * the email_verified gate (FWA-C6-01) and the `https://citrate.ai/entitlement`
 * claim that gates workspace entry.
 */

/** A coarse entitlement tier minted by the spine (DGX_AUTHSPINE §3). */
export interface Entitlement {
  tier?: "public" | "commercial" | "commercial.kyc" | "academic" | "confidential";
  orgId?: string | null;
  citrateRole?: string;
  milestone?: string;
  expiresAt?: number;
}

/** The verified identity, normalized away from any provider's claim shape. */
export interface AuthSession {
  /** Whether this deployment enforces auth (false only in local/mock dev). */
  required: boolean;
  /** Whether the caller presented a valid session. */
  authenticated: boolean;
  /** OIDC subject (stable user id) — the canonical owner key. Never lower-cased. */
  sub?: string;
  /** The user's wallet address (optional claim), lower-cased. */
  walletAddress?: string;
  /**
   * The user's email — ONLY populated when `email_verified === true` in the token
   * (FWA-C6-01). An unverified email is dropped; never trust it for identity.
   */
  email?: string;
  /** Whether the email claim was verified. Mirrors the token's `email_verified`. */
  emailVerified?: boolean;
  /** Coarse access tier; gates workspace entry (RBAC gates per-action). */
  entitlement?: Entitlement;
}

/** Client-side auth state + actions exposed by `useAuth()`. */
export interface AuthContextValue {
  ready: boolean;
  authenticated: boolean;
  sub?: string;
  login: () => void | Promise<void>;
  logout: () => void | Promise<void>;
}

export type AuthMode = "mock" | "oidc";
