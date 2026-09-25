/**
 * Constant-time shared-secret bearer check for machine routes (cron, ops) —
 * PBA-L3c-035. `auth !== \`Bearer ${secret}\`` short-circuits on the first differing byte
 * and leaks the secret's length; comparing SHA-256 digests with timingSafeEqual does
 * neither. An unset/empty secret never matches (callers fail closed before this).
 */
import { createHash, timingSafeEqual } from "node:crypto";

export function bearerMatches(authorization: string | null, secret: string | undefined): boolean {
  if (!secret) return false;
  const presented = (authorization ?? "").replace(/^Bearer\s+/i, "");
  if (!authorization || presented === authorization) return false; // no "Bearer " scheme
  const a = createHash("sha256").update(presented, "utf8").digest();
  const b = createHash("sha256").update(secret, "utf8").digest();
  return timingSafeEqual(a, b);
}
