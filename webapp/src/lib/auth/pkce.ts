/**
 * PKCE (RFC 7636) + OAuth state helpers for the Authorization Code flow against
 * auth.citrate.ai (public client, no secret). Server-side; the verifier + state
 * are held in short-lived httpOnly cookies between /auth/start and the
 * /auth/callback exchange.
 */
import { createHash, randomBytes } from "node:crypto";

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A high-entropy code_verifier (RFC 7636 §4.1: 43–128 chars). */
export function generateVerifier(): string {
  return base64url(randomBytes(32)); // 43 chars
}

/** S256 challenge = base64url(SHA256(verifier)). */
export function challengeS256(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest());
}

/** Opaque anti-CSRF state / nonce. */
export function randomState(): string {
  return base64url(randomBytes(16));
}
