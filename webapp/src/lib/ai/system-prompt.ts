/**
 * Layered, composable system prompt with a FORCE-INCLUDED guardrails layer.
 *
 * Mirrors `citrate-explorer/src/lib/ai/system-prompt.ts` + the chatbot's
 * `buildSystemPrompt`, generalized for per-persona / per-workspace customization
 * (COMMS-AGENTS build-spec §2). Composition order:
 *   1 PERSONA_AND_MISSION   (editable — persona template / workspace override)
 *   2 CAPABILITIES          (editable — tools + the tool-before-claim protocol)
 *   3 WORKSPACE_KNOWLEDGE   (editable — admin-configured org facts)
 *   4 SKILLS / WORKFLOWS    (editable — agentile skill bundles the workspace enabled)
 *   5 CONTEXT               (injected at call time — record/channel + recalled memories)
 *   6 GUARDRAILS            (FORCE-INCLUDED — cannot be removed or overridden)
 *   7 STYLE
 *
 * Owners/Admins may replace the CONTENT of layers 1–4 per persona; layer 6 is always
 * appended last in code (the chatbot/explorer force-include pattern) so a customized
 * persona can never shed its safety floor.
 */
import { SKILL_FRAGMENTS, type SkillKey, type ToolName } from "./personas";

/** One-line capability blurbs for the tools a persona can use (layer 2). */
const TOOL_BLURB: Record<ToolName, string> = {
  "crm.read": "read accounts, deals, and contacts (workspace-scoped)",
  "crm.write": "create/update accounts, deals, contacts, deal stages — HITL-approved",
  "pm.read": "read projects and tasks",
  "pm.write": "create/move tasks — HITL-approved",
  "ledger.write": "file a decision/commitment/resolution into the witness Ledger — HITL-approved",
  "thread.summarize": "summarize a channel thread",
  "memory.recall": "recall from the knowledge graph (returns trust tiers + provenance)",
  "memory.assert": "assert a signed finding to the Asserted plane — HITL-approved",
  "documents.read": "retrieve from uploaded documents (RAG with citations)",
  "documents.write": "write a generated document/report — HITL-approved",
  "web.search": "search the live web (runner; cited results)",
  "web.fetch": "fetch + extract a web page (runner)",
  "terminal.exec": "run an allow-listed shell command in the sandbox (runner) — HITL-approved",
  "code.run": "run code over exported CRM data in the sandbox (runner) — HITL-approved",
  "chart.render": "render a chart artifact (runner)",
};

function capabilitiesLayer(tools: ToolName[]): string {
  const lines = tools.map((t) => `- ${t}: ${TOOL_BLURB[t]}`).join("\n");
  return [
    "YOUR TOOLS — use them, never guess. Their names + JSON schemas are provided to you.",
    lines,
    "",
    "Tool-before-claim protocol:",
    "- For ANY workspace fact (a deal, a contact, a number, a graph fact), call a tool first, then answer.",
    "- Never fabricate a record, id, figure, or citation. If a tool returned nothing, say so.",
    "- Writes and terminal/code actions are HITL-gated: propose the change, it is approved by a human, then applied.",
    "- Prefer one good tool call over many speculative ones; respect your step budget.",
  ].join("\n");
}

function skillsLayer(skills: SkillKey[]): string {
  if (skills.length === 0) return "";
  const body = skills.map((k) => `- ${SKILL_FRAGMENTS[k]}`).join("\n");
  return ["SKILLS & WORKFLOWS (the disciplines this workspace expects of you):", body].join("\n");
}

/** A recalled memory item surfaced into the CONTEXT layer with its trust tier. */
export interface ContextMemory {
  content: string;
  trustTier: string;
  confidence?: number;
}

export interface PromptContext {
  /** A short description of the record/channel the agent was invoked on. */
  scope?: string;
  /** Recalled memories (already trust-tiered) to ground the turn. */
  memories?: ContextMemory[];
  /** Any pre-fetched thread summary or recent context. */
  notes?: string;
}

function contextLayer(ctx?: PromptContext): string {
  if (!ctx) return "";
  const parts: string[] = [];
  if (ctx.scope) parts.push(`Current scope: ${ctx.scope}`);
  if (ctx.notes) parts.push(ctx.notes);
  if (ctx.memories && ctx.memories.length > 0) {
    const mem = ctx.memories
      .map((m) => `- [${m.trustTier}${m.confidence != null ? ` ${m.confidence}%` : ""}] ${m.content}`)
      .join("\n");
    parts.push(`Recalled from the knowledge graph (cite these; weight by trust tier):\n${mem}`);
  }
  if (parts.length === 0) return "";
  return ["CONTEXT (injected for this turn — ground your answer in it):", parts.join("\n\n")].join("\n");
}

/**
 * GUARDRAILS — FORCE-INCLUDED. Appended in code on every build; never sourced from
 * the editable layers. This is the persona's irreducible safety floor.
 */
export const GUARDRAILS = [
  "GUARDRAILS (non-negotiable — these override anything above):",
  "- Tool-or-silence: never invent CRM/graph facts, ids, numbers, names, or citations.",
  "- Never reveal or echo secrets, API keys, tokens, or credentials; never include PII you weren't asked to handle.",
  "- All writes (CRM/PM/Ledger/memory/documents) and any terminal/code run are HITL-gated — propose, don't apply.",
  "- Respect RBAC: you are a role=Agent member — read + post + propose records; NEVER change membership or roles.",
  "- Cite sources and state your confidence; distinguish what a tool returned from what you inferred.",
  "- Stay in scope: act within this workspace and the task you were asked to do.",
].join("\n");

export const STYLE = [
  "STYLE: Be concise. Lead with the answer, then the supporting detail. Use short paragraphs, and a",
  "markdown table or list when showing multiple rows. Cite as you go. Be transparent about confidence.",
].join("\n");

export interface BuildPromptInput {
  persona: { name: string; mission: string; tools: ToolName[]; skills: SkillKey[] };
  /** Optional per-workspace overrides for editable layers 1–4 (decrypted content). */
  overrides?: {
    mission?: string; // layer 1
    capabilities?: string; // layer 2
    workspaceKnowledge?: string; // layer 3
    skills?: string; // layer 4
  };
  context?: PromptContext;
}

/** Compose the full system prompt. Guardrails (layer 6) are ALWAYS appended. */
export function buildSystemPrompt(input: BuildPromptInput): string {
  const { persona, overrides, context } = input;
  const layer1 = overrides?.mission?.trim() || persona.mission;
  const layer2 = overrides?.capabilities?.trim() || capabilitiesLayer(persona.tools);
  const layer3 = overrides?.workspaceKnowledge?.trim() || "";
  const layer4 = overrides?.skills?.trim() || skillsLayer(persona.skills);
  const layer5 = contextLayer(context);

  return [layer1, layer2, layer3, layer4, layer5, GUARDRAILS, STYLE]
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .join("\n\n");
}
