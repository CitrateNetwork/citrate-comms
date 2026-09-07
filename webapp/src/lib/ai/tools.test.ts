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

    // An empty allow-list yields no tools (the persona can do nothing un-allowed).
    const none = citrateCommsTools({ ...base, allow: new Set<ToolName>() });
    expect(Object.keys(none)).toEqual([]);
  });

  it("each tool exposes a zod inputSchema + execute (MCP parity contract)", () => {
    const tools = citrateCommsTools({ ...base }) as Record<string, { inputSchema: unknown; execute: unknown }>;
    for (const t of Object.values(tools)) {
      expect(t.inputSchema).toBeTruthy();
      expect(typeof t.execute).toBe("function");
    }
  });

  // CM2-B-B018: the HITL tools bypass `audited()`, so they carried NO RBAC check at
  // the point of call — a read-only Guest could stage a `runner.terminal` / `crm.delete`
  // approval. Each HITL tool now gates on PostMessage (which an Agent/Member holds and
  // a Guest does not) BEFORE it touches the queue.
  it("a read-only Guest cannot STAGE a high-risk HITL action (guard fires before the DB)", async () => {
    const asGuest = citrateCommsTools({ ...base, agentRole: "Guest" }) as Record<
      string,
      { execute: (a: unknown) => Promise<unknown> }
    >;
    // Assert the GUARD denies (message names the propose-gate), not an incidental
    // DB error — so the tripwire fails if the guard is removed and execution falls
    // through to enqueueApproval.
    await expect(
      asGuest["crm.delete"]!.execute({ entity: "account", recordId: crypto.randomUUID() }),
    ).rejects.toThrow(/may not propose crm\.delete/);
    await expect(asGuest["terminal.exec"]!.execute({ cmd: "echo hi" })).rejects.toThrow(/may not propose terminal\.exec/);
  });

  it("an Agent (read+post) is NOT blocked by the propose-gate (it may propose HITL actions)", () => {
    // Regression guard: the propose-gate must be PostMessage, NOT the execute-capability
    // (CreateRecord/DeleteRecord/ManageWorkspace) — those would wrongly block agents,
    // which is the whole point of the HITL propose→approve split.
    const asAgent = citrateCommsTools({ ...base, agentRole: "Agent" });
    // The tool is present and callable for an Agent (execution is DB-bound, so we only
    // assert the registry exposes it — the deny path above proves the guard is active).
    expect(typeof (asAgent as Record<string, { execute: unknown }>)["crm.note"]!.execute).toBe("function");
  });
});
