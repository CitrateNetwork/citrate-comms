import { describe, it, expect } from "vitest";
import {
  toNotificationEvent,
  subscribeNotify,
  emitNotify,
  NOTIFICATION_EVENT_KEYS,
  type NotifyEvent,
} from "@/lib/realtime/notify-events";

/**
 * E-5 WP-1 — schema-level trust posture. The SSE event payload must carry
 * notification METADATA only, never message bodies. These tests are the
 * runtime half; the compile-time half is the NoBodyGuard in notify-events.ts.
 */
describe("E-5 — notification event schema (server-blind posture)", () => {
  it("toNotificationEvent emits EXACTLY the whitelisted keys — nothing else", () => {
    const event = toNotificationEvent({
      id: "n1",
      kind: "mention",
      actorName: "Ada",
      channelId: "c1",
      channelName: "general",
      createdAt: "2026-07-11T00:00:00.000Z",
    });
    expect(Object.keys(event).sort()).toEqual([...NOTIFICATION_EVENT_KEYS].sort());
  });

  it("structurally drops content-bearing fields smuggled in on the input row", () => {
    // A future caller passing a row that grew a body/messageId must not leak it.
    const dirty = {
      id: "n2",
      kind: "mention",
      actorName: "Ada",
      channelId: "c1",
      channelName: "general",
      createdAt: "2026-07-11T00:00:00.000Z",
      body: "SECRET PLAINTEXT",
      content: "SECRET",
      messageId: "m-123",
    };
    const event = toNotificationEvent(dirty);
    const keys = Object.keys(event);
    for (const forbidden of ["body", "content", "ciphertext", "text", "message", "plaintext", "messageId"]) {
      expect(keys).not.toContain(forbidden);
    }
    expect(JSON.stringify(event)).not.toContain("SECRET");
  });
});

describe("E-5 — in-process notify bus", () => {
  it("delivers to the subscribed recipient only, and unsubscribe stops delivery", () => {
    const got: NotifyEvent[] = [];
    const other: NotifyEvent[] = [];
    const un1 = subscribeNotify("w1", "alice", (e) => got.push(e));
    const un2 = subscribeNotify("w1", "bob", (e) => other.push(e));

    emitNotify("w1", "alice", { type: "unread", unread: 2 });
    expect(got).toHaveLength(1);
    expect(other).toHaveLength(0);

    un1();
    emitNotify("w1", "alice", { type: "unread", unread: 3 });
    expect(got).toHaveLength(1);
    un2();
  });

  it("scopes by workspace — same sub in another workspace hears nothing", () => {
    const got: NotifyEvent[] = [];
    const un = subscribeNotify("w1", "alice", (e) => got.push(e));
    emitNotify("w2", "alice", { type: "unread", unread: 9 });
    expect(got).toHaveLength(0);
    un();
  });
});
