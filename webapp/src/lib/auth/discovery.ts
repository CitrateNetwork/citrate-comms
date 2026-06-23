"use client";

/**
 * OIDC endpoint discovery (client-side). Never hardcode endpoint paths — read the
 * authority's /.well-known/openid-configuration (panva's authorization endpoint is
 * `/auth`, not `/authorize`). Explicit env overrides win; the panva defaults are a
 * last-resort fallback. Cached for the page lifetime. Ported from citrate-dataroom.
 */
import { OIDC_PUBLIC } from "./config";

export interface OidcEndpoints {
  authorization: string;
  token: string;
  userinfo: string;
  endSession?: string;
}

let cached: OidcEndpoints | null = null;

export async function oidcEndpoints(): Promise<OidcEndpoints> {
  if (cached) return cached;
  const issuer = OIDC_PUBLIC.issuer.replace(/\/$/, "");
  let disc: Record<string, string> = {};
  try {
    const r = await fetch(`${issuer}/.well-known/openid-configuration`, { cache: "no-store" });
    if (r.ok) disc = await r.json();
  } catch {
    /* fall back to panva defaults below */
  }
  cached = {
    authorization: OIDC_PUBLIC.authorizeUrl || disc.authorization_endpoint || `${issuer}/auth`,
    token: OIDC_PUBLIC.tokenUrl || disc.token_endpoint || `${issuer}/token`,
    userinfo: disc.userinfo_endpoint || `${issuer}/me`,
    endSession: disc.end_session_endpoint,
  };
  return cached;
}

export function logoutUrl(): string {
  return `${OIDC_PUBLIC.issuer.replace(/\/$/, "")}/logout`;
}
