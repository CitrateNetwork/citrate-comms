/**
 * E-5 WP-1 — SSE stream route. Auth runs the SAME guard chain as the other
 * notifications routes (session → membership → RBAC via requireMember), and
 * the stream carries metadata-only events.
 *
 * Red-first: unauthenticated → 401, non-member → 403, then the happy path.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { requireMember, unreadCount } = vi.hoisted(() => ({
  requireMember: vi.fn(),
  unreadCount: vi.fn(),
}));
vi.mock("@/lib/tenant/guard", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/tenant/guard")>();
  return { ...actual, requireMember };
});
vi.mock("@/lib/domain/notifications", () => ({ unreadCount }));

import { GET } from "./route";
import { GuardError } from "@/lib/tenant/guard";
import { emitNotify, toNotificationEvent } from "@/lib/realtime/notify-events";

const WS = "ws-1";
const params = Promise.resolve({ id: WS });
const req = () => new Request(`http://test/api/workspaces/${WS}/notifications/stream`);

/** Read SSE frames off the response body until `predicate` matches or `n` reads pass. */
async function readEvents(res: Response, count: number): Promise<Record<string, unknown>[]> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const events: Record<string, unknown>[] = [];
  while (events.length < count) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const frame = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const data = frame
        .split("\n")
        .filter((l) => l.startsWith("data: "))
        .map((l) => l.slice(6))
        .join("\n");
      if (data) events.push(JSON.parse(data) as Record<string, unknown>);
    }
  }
  await reader.cancel();
  return events;
}

beforeEach(() => {
  vi.clearAllMocks();
  unreadCount.mockResolvedValue(0);
});
afterEach(() => {
  vi.useRealTimers();
});

describe("E-5 — GET /notifications/stream auth (same guard chain)", () => {
  it("401s an unauthenticated stream request", async () => {
    requireMember.mockRejectedValue(new GuardError(401, "unauthenticated"));
    const res = await GET(req(), { params });
    expect(res.status).toBe(401);
    expect(requireMember).toHaveBeenCalledWith(expect.anything(), WS);
  });

  it("403s a non-member of the workspace", async () => {
    requireMember.mockRejectedValue(new GuardError(403, "not a member of this workspace"));
    const res = await GET(req(), { params });
    expect(res.status).toBe(403);
  });
});

describe("E-5 — stream contents", () => {
  it("opens as text/event-stream and pushes the initial unread snapshot", async () => {
    requireMember.mockResolvedValue({ workspaceId: WS, sub: "alice", role: "member", isAgent: false });
    unreadCount.mockResolvedValue(3);
    const res = await GET(req(), { params });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const [first] = await readEvents(res, 1);
    expect(first).toEqual({ type: "unread", unread: 3 });
  });

  it("pushes emitted notification metadata — and the payload has NO body field", async () => {
    requireMember.mockResolvedValue({ workspaceId: WS, sub: "alice", role: "member", isAgent: false });
    unreadCount.mockResolvedValue(1);
    const res = await GET(req(), { params });
    const pending = readEvents(res, 2);
    // Give the stream a tick to subscribe, then emit for THIS recipient.
    await new Promise((r) => setTimeout(r, 20));
    emitNotify(WS, "alice", toNotificationEvent({
      id: "n1",
      kind: "mention",
      actorName: "Ada",
      channelId: "c1",
      channelName: "general",
      createdAt: "2026-07-11T00:00:00.000Z",
    }));
    const events = await pending;
    const notif = events.find((e) => e.type === "notification");
    expect(notif).toBeDefined();
    expect(notif!.id).toBe("n1");
    for (const forbidden of ["body", "content", "ciphertext", "text", "message", "plaintext", "messageId"]) {
      expect(Object.keys(notif!)).not.toContain(forbidden);
    }
  });

  it("does not leak another recipient's events into alice's stream", async () => {
    requireMember.mockResolvedValue({ workspaceId: WS, sub: "alice", role: "member", isAgent: false });
    unreadCount.mockResolvedValue(0);
    const res = await GET(req(), { params });
    const pending = readEvents(res, 1); // only the initial snapshot should arrive
    await new Promise((r) => setTimeout(r, 20));
    emitNotify(WS, "bob", toNotificationEvent({
      id: "n-bob",
      kind: "mention",
      actorName: "Ada",
      channelId: "c1",
      channelName: "general",
      createdAt: "2026-07-11T00:00:00.000Z",
    }));
    const events = await pending;
    expect(events).toHaveLength(1);
    expect(events[0]?.type).toBe("unread");
  });
});
