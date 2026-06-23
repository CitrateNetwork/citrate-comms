/**
 * Fail-closed rate limiting (Upstash). Applied to auth, invite, join, message-send
 * and witness routes.
 *
 * FAIL-CLOSED: if Upstash is not configured or unreachable, `limit()` DENIES the
 * request rather than letting it through (WEB-1 posture). A Tier-1 app's gate must
 * not silently disable its rate limit because Redis blipped.
 */
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

export interface LimitResult {
  success: boolean;
  remaining: number;
}

let limiter: Ratelimit | null = null;
let configured = false;

function get(): Ratelimit | null {
  if (configured) return limiter;
  configured = true;
  // Accept either the Upstash names or the Vercel KV / Marketplace names.
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  if (!url || !token) {
    limiter = null;
    return null;
  }
  limiter = new Ratelimit({
    redis: new Redis({ url, token }),
    limiter: Ratelimit.slidingWindow(20, "60 s"),
    prefix: "comms:rl",
    analytics: false,
  });
  return limiter;
}

/**
 * Rate-limit by an opaque key (e.g. hashed IP + route). Returns success:false when
 * over the limit OR when the limiter is unavailable (fail closed).
 */
export async function limit(key: string): Promise<LimitResult> {
  const rl = get();
  if (!rl) return { success: false, remaining: 0 };
  try {
    const r = await rl.limit(key);
    return { success: r.success, remaining: r.remaining };
  } catch {
    return { success: false, remaining: 0 };
  }
}

/** True only when a real limiter is configured (for tests / health checks). */
export function rateLimitConfigured(): boolean {
  return get() !== null;
}
