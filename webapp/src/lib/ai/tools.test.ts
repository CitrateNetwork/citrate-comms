import { describe, expect, it } from "vitest";
import { citrateCommsTools, IMPLEMENTED_TOOLS } from "./tools";
import type { ToolName } from "./personas";

const base = { workspaceId: "ws-1", invokedBySub: "user-1", agentRole: "Agent" as const };

describe("comms tool registry — single source of truth", () => {
  it("returns only IMPLEMENTED tools, never unimplemented declared ones", () => {
    const tools = citrateCommsTools({ ...base });
    const keys = Object.keys(tools);
    for (const k of keys) expect(IMPLEMENTED_TOOLS).toContain(k as ToolName);
    expect(keys).toContain("crm.read");
    expect(keys).toContain("memory.recall");
    expect(keys).toContain("memory.assert");
    expect(keys).toContain("crm.note");
    expect(keys).toContain("crm.write");
  });

  it("respects the persona allow-list (intersection with implemented)", () => {
    const onlyCrm = citrateCommsTools({ ...base, allow: new Set<ToolName>(["crm.read"]) });
    expect(Object.keys(onlyCrm)).toEqual(["crm.read"]);

    // A persona that only declares not-yet-implemented tools gets an empty (safe) set.
    const future = citrateCommsTools({ ...base, allow: new Set<ToolName>(["web.search", "terminal.exec"]) });
    expect(Object.keys(future)).toEqual([]);
  });

  it("each tool exposes a zod inputSchema + execute (MCP parity contract)", () => {
    const tools = citrateCommsTools({ ...base }) as Record<string, { inputSchema: unknown; execute: unknown }>;
    for (const t of Object.values(tools)) {
      expect(t.inputSchema).toBeTruthy();
      expect(typeof t.execute).toBe("function");
    }
  });
});
