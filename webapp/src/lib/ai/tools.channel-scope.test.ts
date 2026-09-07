/**
 * CM2-B-B003: channel-scoped tools must authorize on channel MEMBERSHIP, not just the
 * ReadChannel/PostMessage capability. Without the predicate a prompt-injected agent (or
 * a Guest reaching the registry) could read/write any channel or DM in the workspace by
 * uuid. Membership is mocked so this stays DB-free.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const isChannelMember = vi.fn();
const listMessages = vi.fn();
const postAndPin = vi.fn();

vi.mock("@/lib/domain/channels", async (o) => ({ ...(await o()), isChannelMember: (c: string, s: string) => isChannelMember(c, s) }));
vi.mock("@/lib/domain/messages", async (o) => ({ ...(await o()), listMessages: (...a: unknown[]) => listMessages(...a) }));
vi.mock("@/lib/domain/calendar", async (o) => ({ ...(await o()), postAndPinCalendarSummary: (...a: unknown[]) => postAndPin(...a) }));

import { citrateCommsTools } from "./tools";

const CHAN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
function tools() {
  return citrateCommsTools({ workspaceId: "ws-1", invokedBySub: "agent-1", agentRole: "Agent", audit: false }) as Record<
    string,
    { execute: (a: unknown) => Promise<unknown> }
  >;
}

describe("channel-scoped tool authorization (CM2-B-B003)", () => {
  beforeEach(() => {
    isChannelMember.mockReset();
    listMessages.mockReset();
    postAndPin.mockReset();
  });

  it("thread.summarize refuses a channel the invoker is NOT seated in", async () => {
    isChannelMember.mockResolvedValue(false);
    await expect(tools()["thread.summarize"]!.execute({ channelId: CHAN, limit: 50 })).rejects.toThrow(/not a member/);
    expect(listMessages).not.toHaveBeenCalled();
  });

  it("thread.summarize returns messages for a channel the invoker IS in", async () => {
    isChannelMember.mockResolvedValue(true);
    listMessages.mockResolvedValue([{ authorSub: "a", body: "hello", createdAt: "2026-01-01" }]);
    const r = (await tools()["thread.summarize"]!.execute({ channelId: CHAN, limit: 50 })) as { messages: { body: string }[] };
    expect(r.messages[0]!.body).toBe("hello");
  });

  it("calendar.pin_summary refuses to post into a channel the invoker is NOT in", async () => {
    isChannelMember.mockResolvedValue(false);
    await expect(tools()["calendar.pin_summary"]!.execute({ channelId: CHAN, days: 7 })).rejects.toThrow(/not a member/);
    expect(postAndPin).not.toHaveBeenCalled();
  });
});
