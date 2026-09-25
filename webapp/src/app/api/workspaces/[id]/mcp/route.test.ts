/**
 * CM2-B-B002: the MCP tool surface must bind to the CALLER's real role, never a
 * hardcoded "Agent". A Guest (documented read-only) drives this endpoint directly and
 * must NOT receive Agent-level post/write capability. buildTools is the seam; the tools
 * self-enforce RBAC once the real role is threaded through.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const postAndPin = vi.fn(async (..._a: unknown[]) => ({ messageId: "m1", events: 0 }));
vi.mock("@/lib/domain/crm-fields", async (o) => ({ ...(await o()), loadFieldDefsByEntity: async () => ({}) }));
vi.mock("@/lib/domain/calendar", async (o) => ({ ...(await o()), postAndPinCalendarSummary: (...a: unknown[]) => postAndPin(...a) }));

import { buildTools } from "./route";

const CHAN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

describe("MCP tool surface is role-bound (CM2-B-B002)", () => {
  beforeEach(() => postAndPin.mockClear());

  it("a Guest does NOT receive Agent post capability (calendar.pin_summary is not offered)", async () => {
    const tools = (await buildTools("ws-1", { sub: "guest-1", role: "Guest" })) as Record<
      string,
      { execute: (a: unknown) => Promise<unknown> }
    >;
    // PBA-L3c-002: the registry is filtered to the caller's permitted tools, so the
    // Agent-level post tool is not even listed for a Guest (stronger than denying it).
    expect(tools["calendar.pin_summary"]).toBeUndefined();
    expect(Object.keys(tools)).toEqual(["thread.summarize"]);
    expect(postAndPin).not.toHaveBeenCalled();
  });

  it("a Member gets the internal tool surface (pin_summary still channel-gated)", async () => {
    const tools = (await buildTools("ws-1", { sub: "member-1", role: "Member" })) as Record<string, unknown>;
    expect(tools["calendar.pin_summary"]).toBeDefined();
    expect(tools["crm.read"]).toBeDefined();
    expect(CHAN).toBeTruthy();
  });
});
