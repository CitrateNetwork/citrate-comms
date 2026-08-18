import { describe, it, expect } from "vitest";
import { groupNotifs, type NotifItem } from "./notif-group";

function n(p: Partial<NotifItem>): NotifItem {
  return { id: "i", kind: "mention", actorName: "Ada", channelId: null, channelName: null, taskId: null, read: false, createdAt: "2026-08-17T00:00:00Z", ...p };
}

describe("groupNotifs", () => {
  it("groups mentions/DMs by channel and assignments under Tasks", () => {
    const groups = groupNotifs([
      n({ id: "1", channelId: "c1", channelName: "general" }),
      n({ id: "2", channelId: "c1", channelName: "general" }),
      n({ id: "3", channelId: "c2", channelName: "random", read: true }),
      n({ id: "4", kind: "task_assigned", taskId: "t1" }),
    ]);
    const byKey = new Map(groups.map((g) => [g.key, g]));
    expect(byKey.get("c1")!.items.length).toBe(2);
    expect(byKey.get("c1")!.name).toBe("general");
    expect(byKey.get("c1")!.icon).toBe("hash");
    expect(byKey.get("tasks")!.name).toBe("Tasks");
    expect(byKey.get("tasks")!.icon).toBe("projects");
  });

  it("counts only UNREAD per group", () => {
    const [g] = groupNotifs([
      n({ id: "1", channelId: "c1", channelName: "g", read: false }),
      n({ id: "2", channelId: "c1", channelName: "g", read: true }),
    ]);
    expect(g!.unread).toBe(1);
    expect(g!.items.length).toBe(2);
  });

  it("falls back gracefully when a channel name is missing", () => {
    const [g] = groupNotifs([n({ id: "1", channelId: "cX", channelName: null })]);
    expect(g!.name).toBe("Conversation");
  });
});
