/**
 * Egress-restricted web-fetch for the agent runner path.
 *
 * The agent runner is a separate daemon co-located with internal infrastructure. Handing
 * it a raw, agent-supplied URL means the daemon opens the socket on its own — resolving
 * DNS and following redirects outside this process's control — so a pre-flight check on
 * the BFF cannot bound where that connection actually lands. Instead of delegating a raw
 * URL, the BFF performs the fetch itself through the pinned, guarded client in
 * `@/lib/research/fetch`, which:
 *   - allows only http/https schemes;
 *   - resolves the host and refuses if ANY resolved address is non-public
 *     (loopback / private / link-local / CGNAT / IPv4-mapped / translation ranges),
 *     via `isBlockedAddress`;
 *   - pins the connection to a validated address (the connect-time lookup re-checks, so a
 *     value that changes between validation and connect cannot be reached);
 *   - re-validates the destination on EVERY redirect hop, with a hop cap.
 *
 * This restricts the runner web-fetch egress to public destinations at connection time,
 * not merely at pre-flight. A disallowed destination throws {@link BlockedUrlError} with a
 * non-leaky message.
 */
import { fetchReadable, BlockedUrlError, type FetchReadableOptions } from "@/lib/research/fetch";

export { BlockedUrlError };

export interface RunnerFetchResult {
  url: string;
  title: string;
  text: string;
}

/**
 * Fetch an agent-supplied URL for the runner path, restricted to public destinations.
 * Throws {@link BlockedUrlError} if the target (or any redirect hop) is not public.
 * `opts` is test-only injection for the connecting path; production callers omit it.
 */
export async function runnerWebFetch(url: string, opts?: FetchReadableOptions): Promise<RunnerFetchResult> {
  const page = await fetchReadable(url, opts);
  if (page.blocked) {
    // Non-leaky: do not echo which internal address / hop was refused.
    throw new BlockedUrlError("destination not allowed");
  }
  return { url: page.url, title: page.title, text: page.text };
}
