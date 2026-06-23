import { NextResponse } from "next/server";
import { OIDC_PUBLIC, FLOW_COOKIE } from "@/lib/auth/config";
import { serializeFlowCookie } from "@/lib/auth/cookies";
import { generateVerifier, challengeS256, randomState } from "@/lib/auth/pkce";

/**
 * Begin the Authorization Code + PKCE flow against auth.citrate.ai. Generates a
 * verifier + state, stashes them in short-lived httpOnly cookies, and 303s to the
 * authority's `/auth` endpoint (panva's authorization endpoint is `/auth`). The
 * authority's own interaction page offers email/passkey/Google/wallet — we just
 * request the scopes. `?returnTo=` is preserved through the round-trip.
 */
export const runtime = "nodejs";

function authorizeEndpoint(): string {
  const issuer = OIDC_PUBLIC.issuer.replace(/\/$/, "");
  return OIDC_PUBLIC.authorizeUrl || `${issuer}/auth`;
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const origin = url.origin;
  const returnTo = url.searchParams.get("returnTo") || "/";

  const verifier = generateVerifier();
  const state = randomState();
  const challenge = challengeS256(verifier);

  // Request a refresh token. `offline_access` is required for the refresh_token
  // grant, and panva (per the OIDC spec) only GRANTS it when `prompt=consent` is
  // present — without it, offline_access is silently dropped and no refresh token
  // is issued. citrate-comms-web is a trusted first-party client, so the authority
  // auto-resolves the consent prompt server-side (no visible screen). Mirrors
  // citrate-explorer's TD-9 flow. Append + dedupe so it works without an env change.
  const scope = Array.from(new Set([...OIDC_PUBLIC.scope.split(/\s+/).filter(Boolean), "offline_access"])).join(" ");

  const authUrl = new URL(authorizeEndpoint());
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", OIDC_PUBLIC.clientId);
  authUrl.searchParams.set("redirect_uri", `${origin}${OIDC_PUBLIC.redirectPath}`);
  authUrl.searchParams.set("scope", scope);
  authUrl.searchParams.set("prompt", "consent");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const res = NextResponse.redirect(authUrl.toString(), { status: 303 });
  res.headers.append("set-cookie", serializeFlowCookie(FLOW_COOKIE.verifier, verifier));
  res.headers.append("set-cookie", serializeFlowCookie(FLOW_COOKIE.state, state));
  res.headers.append("set-cookie", serializeFlowCookie(FLOW_COOKIE.returnTo, returnTo));
  return res;
}
