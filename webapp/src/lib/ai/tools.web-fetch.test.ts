/**
 * CM2-B-B006: web.fetch must NOT escalate an SSRF-blocked URL to the runner's
 * unguarded Playwright fetcher. A `blocked` page returns immediately; the runner is
 * only reached when static extraction was genuinely thin (available, short text).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const fetchReadable = vi.fn();
const webFetch = vi.fn();

vi.mock("@/lib/research/fetch", () => ({ fetchReadable: (u: string) => fetchReadable(u) }));
vi.mock("./runner", async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return { ...actual, webFetch: (u: string) => webFetch(u) };
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

describe("web.fetch SSRF escalation guard (CM2-B-B006)", () => {
  beforeEach(() => {
    fetchReadable.mockReset();
    webFetch.mockReset();
  });

  it("does NOT call the runner when the static fetch was SSRF-blocked", async () => {
    fetchReadable.mockResolvedValue({
      url: "http://169.254.169.254/latest/meta-data/",
      title: "",
      text: "",
      truncated: false,
      available: false,
      blocked: true,
      note: "private address not allowed",
    });
    const res = (await webFetchTool().execute({ url: "http://169.254.169.254/latest/meta-data/" })) as {
      blocked?: boolean;
      available: boolean;
    };
    expect(webFetch).not.toHaveBeenCalled();
    expect(res.blocked).toBe(true);
    expect(res.available).toBe(false);
  });

  it("does NOT escalate a thin page unless the runner is attested as SSRF-guarded (PBA-L3c-010)", async () => {
    delete process.env.COMMS_RUNNER_FETCH_GUARDED;
    fetchReadable.mockResolvedValue({ url: "https://ex.com", title: "", text: "short", truncated: false, available: true });
    webFetch.mockResolvedValue({ url: "https://ex.com", title: "t", text: "the full dynamic body" });
    const res = (await webFetchTool().execute({ url: "https://ex.com" })) as { text: string };
    expect(webFetch).not.toHaveBeenCalled();
    expect(res.text).toBe("short");
  });

  it("DOES escalate a thin page when COMMS_RUNNER_FETCH_GUARDED=1", async () => {
    process.env.COMMS_RUNNER_FETCH_GUARDED = "1";
    try {
      fetchReadable.mockResolvedValue({ url: "https://ex.com", title: "", text: "short", truncated: false, available: true });
      webFetch.mockResolvedValue({ url: "https://ex.com", title: "t", text: "the full dynamic body" });
      const res = (await webFetchTool().execute({ url: "https://ex.com" })) as { text: string };
      expect(webFetch).toHaveBeenCalledOnce();
      expect(res.text).toBe("the full dynamic body");
    } finally {
      delete process.env.COMMS_RUNNER_FETCH_GUARDED;
    }
  });
});
