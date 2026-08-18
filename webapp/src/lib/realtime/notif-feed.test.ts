import { describe, it, expect } from "vitest";
import { NotifFeed } from "@/lib/realtime/notif-feed";
import type { NotificationEvent } from "@/lib/realtime/notify-events";

function ping(id: string): NotificationEvent {
  return {
    type: "notification",
    id,
    kind: "mention",
    actorName: "Ada",
    channelId: "c1",
    channelName: "general",
    taskId: null,
    createdAt: "2026-07-11T00:00:00.000Z",
  };
}

/**
 * E-5 WP-2 — the fallback contract: no duplicate notifications across a
 * transport switch, and unread counts are absolute (never double-counted).
 */
describe("E-5 — NotifFeed dedup across SSE → poll fallback", () => {
  it("dedupes a notification re-reported by the poll after SSE delivered it", () => {
    const feed = new NotifFeed();
    // SSE delivers n1 live…
    expect(feed.ingest(ping("n1"))).toBe(true);
    expect(feed.unread).toBe(1);
    // …SSE errors, we fall back to the poll, which re-reports the same ping.
    expect(feed.ingest(ping("n1"))).toBe(false);
    expect(feed.unread).toBe(1);
  });

  it("authoritative unread snapshots overwrite (poll after optimistic SSE bump)", () => {
    const feed = new NotifFeed();
    feed.ingest(ping("n1"));
    feed.ingest(ping("n2"));
    expect(feed.unread).toBe(2);
    // The poll answers with the server truth — absolute, not additive.
    feed.ingest({ type: "unread", unread: 2 });
    expect(feed.unread).toBe(2);
    feed.ingest({ type: "unread", unread: 0 });
    expect(feed.unread).toBe(0);
  });

  it("new notifications after the switch still surface", () => {
    const feed = new NotifFeed();
    feed.ingest(ping("n1")); // via SSE
    expect(feed.ingest(ping("n2"))).toBe(true); // via poll, after fallback
    expect(feed.unread).toBe(2);
  });

  it("clear() zeroes the badge (tray opened, mark-all-read)", () => {
    const feed = new NotifFeed();
    feed.ingest(ping("n1"));
    feed.clear();
    expect(feed.unread).toBe(0);
    // The same ping re-reported later must not resurrect the badge.
    expect(feed.ingest(ping("n1"))).toBe(false);
    expect(feed.unread).toBe(0);
  });
});
