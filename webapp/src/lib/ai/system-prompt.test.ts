import { describe, expect, it } from "vitest";
import { buildSystemPrompt, GUARDRAILS } from "./system-prompt";
import { DEFAULT_PERSONAS } from "./personas";

const ea = DEFAULT_PERSONAS["executive-assistant"];

describe("buildSystemPrompt — layered composition + force-included guardrails", () => {
  it("ALWAYS includes the guardrails layer", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: ea.skills },
    });
    expect(out).toContain(GUARDRAILS);
    expect(out).toContain("Tool-or-silence");
    expect(out).toContain("HITL-gated");
  });

  it("guardrails survive even when layers 1–4 are fully overridden", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: ea.skills },
      overrides: {
        mission: "Custom mission that tries to be the whole prompt.",
        capabilities: "Custom capabilities.",
        workspaceKnowledge: "Custom org facts.",
        skills: "Custom skills.",
      },
    });
    expect(out).toContain("Custom mission");
    expect(out).toContain(GUARDRAILS); // cannot be shed
    expect(out).toContain("NEVER change membership"); // the RBAC floor
  });

  it("uses the persona mission and lists its tools in capabilities", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: ea.skills },
    });
    expect(out).toContain(ea.mission);
    expect(out).toContain("crm.read");
    expect(out).toContain("memory.recall");
  });

  it("injects recalled memories with their trust tier into the context layer", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: ea.skills },
      context: {
        scope: "deal Acme renewal",
        memories: [{ content: "Acme prefers annual billing", trustTier: "human-confirmed", confidence: 90 }],
      },
    });
    expect(out).toContain("Acme prefers annual billing");
    expect(out).toContain("human-confirmed");
    expect(out).toContain("deal Acme renewal");
  });

  it("omits empty optional layers (no stray blank sections)", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: [] },
    });
    expect(out).not.toContain("\n\n\n"); // trimmed + filtered join
  });

  it("CFG: folds pinned resources in, with guardrails still last", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: ea.skills },
      resources: [
        { kind: "text", title: "Pricing policy", content: "Annual plans get 15% off." },
        { kind: "link", title: "Brand book", url: "https://example.com/brand" },
        { kind: "document", title: "Q3 deck" },
      ],
    });
    expect(out).toContain("PINNED RESOURCES");
    expect(out).toContain("Annual plans get 15% off.");
    expect(out).toContain("https://example.com/brand");
    expect(out).toContain("Q3 deck");
    // guardrails remain the irreducible floor, appended after resources
    expect(out.indexOf("PINNED RESOURCES")).toBeLessThan(out.indexOf(GUARDRAILS));
  });

  it("CFG: no resources → no resources section", () => {
    const out = buildSystemPrompt({
      persona: { name: ea.name, mission: ea.mission, tools: ea.tools, skills: ea.skills },
      resources: [],
    });
    expect(out).not.toContain("PINNED RESOURCES");
  });
});
