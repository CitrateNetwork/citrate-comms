/**
 * E-5 WP-2 — client-side notification feed state, transport-agnostic.
 *
 * NotifBell can hear about notifications over TWO transports (SSE push, and
 * the 20s poll it falls back to). This tiny state machine is the contract that
 * makes the switch safe: notification events are deduplicated by id (a ping
 * seen over SSE is NOT re-surfaced when the poll re-reports it), and unread
 * counts are absolute snapshots (last write wins, never summed across
 * transports). Pure + injectable so it is unit-testable without EventSource.
 */
import type { NotifyEvent } from "@/lib/realtime/notify-events";

export type Transport = "sse" | "poll";

export class NotifFeed {
  private seen = new Set<string>();
  private unreadCount = 0;

  /** Current unread badge value. */
  get unread(): number {
    return this.unreadCount;
  }

  /** Authoritative absolute count (from a poll response or an SSE unread event). */
  setUnread(n: number): void {
    this.unreadCount = Math.max(0, n);
  }

  /**
   * Ingest one event from EITHER transport. Returns true iff the event changed
   * state (i.e. it was not a duplicate notification already seen elsewhere).
   */
  ingest(event: NotifyEvent): boolean {
    if (event.type === "unread") {
      this.setUnread(event.unread);
      return true;
    }
    if (this.seen.has(event.id)) return false; // duplicate across transports — drop
    this.seen.add(event.id);
    // Optimistic bump; the next authoritative unread snapshot reconciles it.
    this.unreadCount += 1;
    return true;
  }

  /** Tray opened + mark-all-read succeeded. */
  clear(): void {
    this.unreadCount = 0;
  }
}
