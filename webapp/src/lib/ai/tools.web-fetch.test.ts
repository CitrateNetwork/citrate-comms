/**
 * web.fetch escalation behavior:
 *  - a blocked page is returned immediately and never escalated;
 *  - a thin page is escalated ONLY when COMMS_RUNNER_FETCH_GUARDED=1, and escalation goes
 *    through the egress-restricted BFF client (runnerWebFetch), never a raw runner call;
 *  - when the egress client refuses the destination, the tool returns a blocked result
 *    rather than throwing or falling through to a less-guarded fetch;
 *  - with the flag unset, behavior is unchanged (no escalation).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { BlockedUrlError } from "@/lib/research/fetch";

const fetchReadable = vi.fn();
const runnerWebFetch = vi.fn();

// Keep the real BlockedUrlError so the tool's `instanceof` check works; stub fetchReadable.
vi.mock("@/lib/research/fetch", async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return { ...actual, fetchReadable: (u: string) => fetchReadable(u) };
});
vi.mock("./runner-fetch", async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return { ...actual, runnerWebFetch: (u: string) => runnerWebFetch(u) };
});

import { citrateCommsTools } from "./tools";

function webFetchTool() {
  const tools = citrateCommsTools({
    workspaceId: "ws-1",
    invokedBySub: "user-1",
    agentRole: "Agent",
    audit: false, // incognito → no transparency-log DB write
  }) as Record<string, { execute: (a: unknown) => Promise<unknown> }>;
  return tools["web.fetch"]!;
}

describe("web.fetch escalation", () => {
  beforeEach(() => {
    fetchReadable.mockReset();
    runnerWebFetch.mockReset();
    delete process.env.COMMS_RUNNER_FETCH_GUARDED;
  });

  it("returns a blocked page immediately and never escalates it", async () => {
    process.env.COMMS_RUNNER_FETCH_GUARDED = "1"; // even with escalation enabled
    fetchReadable.mockResolvedValue({
      url: "http://169.254.169.254/",
      title: "",
      text: "",
      truncated: false,
      available: false,
      blocked: true,
      note: "private address not allowed",
    });
    const res = (await webFetchTool().execute({ url: "http://169.254.169.254/" })) as {
      blocked?: boolean;
      available: boolean;
    };
    expect(runnerWebFetch).not.toHaveBeenCalled();
    expect(res.blocked).toBe(true);
    expect(res.available).toBe(false);
  });

  it("with the flag unset, does not escalate a thin page (behavior unchanged)", async () => {
    fetchReadable.mockResolvedValue({ url: "https://ex.com", title: "", text: "short", truncated: false, available: true });
    runnerWebFetch.mockResolvedValue({ url: "https://ex.com", title: "t", text: "the full dynamic body" });
    const res = (await webFetchTool().execute({ url: "https://ex.com" })) as { text: string };
    expect(runnerWebFetch).not.toHaveBeenCalled();
    expect(res.text).toBe("short");
  });

  it("with the flag set, escalates a thin page through the egress-restricted client", async () => {
    process.env.COMMS_RUNNER_FETCH_GUARDED = "1";
    fetchReadable.mockResolvedValue({ url: "https://ex.com", title: "", text: "short", truncated: false, available: true });
    runnerWebFetch.mockResolvedValue({ url: "https://ex.com", title: "t", text: "the full dynamic body" });
    const res = (await webFetchTool().execute({ url: "https://ex.com" })) as { text: string };
    expect(runnerWebFetch).toHaveBeenCalledOnce();
    expect(res.text).toBe("the full dynamic body");
  });

  it("returns a blocked result (not a throw) when the egress client refuses the escalation", async () => {
    process.env.COMMS_RUNNER_FETCH_GUARDED = "1";
    fetchReadable.mockResolvedValue({ url: "https://ex.com", title: "", text: "short", truncated: false, available: true });
    runnerWebFetch.mockRejectedValue(new BlockedUrlError("destination not allowed"));
    const res = (await webFetchTool().execute({ url: "https://ex.com" })) as { blocked?: boolean; available: boolean; note?: string };
    expect(runnerWebFetch).toHaveBeenCalledOnce();
    expect(res.blocked).toBe(true);
    expect(res.available).toBe(false);
    expect(res.note).toBe("blocked"); // no internal detail leaked
  });
});
