import { describe, expect, it } from "vitest";
import {
  DEFAULT_PERSONAS,
  DEFAULT_PERSONA_LIST,
  HITL_TOOLS,
  RUNNER_TOOLS,
  SKILL_FRAGMENTS,
  type SkillKey,
  type ToolName,
} from "./personas";

const ALL_TOOLS: ToolName[] = [
  "crm.read", "crm.write", "crm.note", "pm.read", "pm.write", "ledger.write", "thread.summarize",
  "memory.recall", "memory.assert", "documents.read", "documents.write",
  "web.search", "web.fetch", "terminal.exec", "code.run", "chart.render",
];

describe("default personas", () => {
  it("ships exactly the three org-default personas", () => {
    expect(DEFAULT_PERSONA_LIST).toHaveLength(3);
    expect(Object.keys(DEFAULT_PERSONAS).sort()).toEqual([
      "data-scientist-notetaker",
      "executive-assistant",
      "marketing-growth-engineer",
    ]);
  });

  it("each persona has a valid tool allow-list, model, and step budget", () => {
    for (const p of DEFAULT_PERSONA_LIST) {
      expect(p.tools.length).toBeGreaterThan(0);
      for (const t of p.tools) expect(ALL_TOOLS).toContain(t);
      expect(p.maxSteps).toBeGreaterThanOrEqual(6);
      expect(p.temperature).toBeGreaterThanOrEqual(0);
      expect(p.temperature).toBeLessThanOrEqual(1);
      expect(typeof p.model.gateway).toBe("string");
    }
  });

  it("every referenced skill has a prompt fragment", () => {
    const referenced = new Set<SkillKey>(DEFAULT_PERSONA_LIST.flatMap((p) => p.skills));
    for (const k of referenced) expect(SKILL_FRAGMENTS[k]).toBeTruthy();
  });

  it("HITL tools are mutating/terminal, runner tools are privileged", () => {
    expect(HITL_TOOLS.has("crm.write")).toBe(true);
    expect(HITL_TOOLS.has("crm.note")).toBe(true); // agent-added notes are approval-gated
    expect(HITL_TOOLS.has("terminal.exec")).toBe(true);
    expect(HITL_TOOLS.has("crm.read")).toBe(false); // reads are not gated
    expect(RUNNER_TOOLS.has("web.search")).toBe(true);
    expect(RUNNER_TOOLS.has("memory.recall")).toBe(false); // inline BFF tool
  });

  it("the notetaker is the only persona with terminal/code (sandbox) tools", () => {
    const withTerminal = DEFAULT_PERSONA_LIST.filter((p) => p.tools.includes("terminal.exec"));
    expect(withTerminal.map((p) => p.key)).toEqual(["data-scientist-notetaker"]);
  });
});
