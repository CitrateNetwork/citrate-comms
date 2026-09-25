import { describe, expect, it } from "vitest";
import { citrateCommsTools, IMPLEMENTED_TOOLS, TOOL_CAPABILITY, CHANNEL_SCOPED_TOOLS, toolPermitted } from "./tools";
import { Capability, can, type Role } from "@/lib/rbac/matrix";
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

  // CM2-B-B018: the HIC tools skip `audited()`, so they carried NO RBAC check at
  // the point of call — a read-only Guest could stage a `runner.terminal` / `crm.delete`
  // approval. Each HIC tool now gates on PostMessage (which an Agent/Member holds and
  // a Guest does not) BEFORE it touches the queue.
  it("a read-only Guest cannot STAGE a high-risk HIC action (the tool is not even offered)", () => {
    // PBA-L3c-002: the registry is filtered by toolPermitted, so the propose tools are
    // absent for a Guest; the execute-time assertPropose is defense in depth behind it.
    const asGuest = citrateCommsTools({ ...base, agentRole: "Guest" }) as Record<string, unknown>;
    expect(asGuest["crm.delete"]).toBeUndefined();
    expect(asGuest["terminal.exec"]).toBeUndefined();
    expect(toolPermitted("crm.delete", "Guest")).toBe(false);
    expect(toolPermitted("terminal.exec", "Guest")).toBe(false);
  });

  it("an agent invoked by an EXTERNAL human gets only channel-scoped tools (no borrowed read)", () => {
    for (const invokerRole of ["Partner", "Guest"] as const) {
      const t = citrateCommsTools({ ...base, agentRole: "Agent", invokerRole });
      expect(Object.keys(t)).toEqual(["thread.summarize"]);
    }
    const internal = citrateCommsTools({ ...base, agentRole: "Agent", invokerRole: "Member" });
    expect(Object.keys(internal)).toContain("crm.read");
  });

  it("toolPermitted matches rbac/matrix.ts for every implemented tool x role pair (tripwire)", () => {
    const roles: Role[] = ["Owner", "Admin", "Member", "Partner", "Guest", "Agent"];
    for (const name of IMPLEMENTED_TOOLS) {
      const cap = TOOL_CAPABILITY[name];
      expect(cap, `${name} has no declared capability`).toBeDefined();
      for (const agentRole of roles) {
        for (const invokerRole of roles) {
          const expected =
            can(agentRole, cap!) && can(invokerRole, cap!) &&
            (CHANNEL_SCOPED_TOOLS.has(name) || (can(agentRole, Capability.ReadWorkspace) && can(invokerRole, Capability.ReadWorkspace)));
          expect(toolPermitted(name, agentRole, invokerRole), `${name} agent=${agentRole} invoker=${invokerRole}`).toBe(expected);
        }
      }
      // External roles never reach a workspace-data tool.
      if (!CHANNEL_SCOPED_TOOLS.has(name)) {
        expect(toolPermitted(name, "Partner")).toBe(false);
        expect(toolPermitted(name, "Guest")).toBe(false);
      }
    }
    expect(toolPermitted("no.such.tool", "Owner")).toBe(false);
    expect([...CHANNEL_SCOPED_TOOLS]).toEqual(["thread.summarize"]);
  });

  it("an Agent (read+post) is NOT blocked by the propose-gate (it may propose HIC actions)", () => {
    // Regression guard: the propose-gate must be PostMessage, NOT the execute-capability
    // (CreateRecord/DeleteRecord/ManageWorkspace) — those would wrongly block agents,
    // which is the whole point of the HIC propose→approve split.
    const asAgent = citrateCommsTools({ ...base, agentRole: "Agent" });
    // The tool is present and callable for an Agent (execution is DB-bound, so we only
    // assert the registry exposes it — the deny path above proves the guard is active).
    expect(typeof (asAgent as Record<string, { execute: unknown }>)["crm.note"]!.execute).toBe("function");
  });
});
