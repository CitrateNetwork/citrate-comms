/**
 * MEN-1 — call an agent into a channel. When a member @-mentions an agent in a channel, the
 * agent (a real Agent-role member) reads the recent channel context through its persona and
 * posts ONE reply back into the channel as itself. Read-only by design: the channel auto-reply
 * path drops every HITL/mutating tool (writes still go through the approvals queue elsewhere),
 * so an @-ping can never silently mutate CRM/PM data. Every run is audited.
 */
import { generateText, stepCountIs } from "ai";
import { getInferenceModel } from "@/lib/ai/provider";
import { buildSystemPrompt } from "@/lib/ai/system-prompt";
import { citrateCommsTools } from "@/lib/ai/tools";
import { HITL_TOOLS } from "@/lib/ai/personas";
import { resolvePersona, personaIdForAgent } from "@/lib/domain/personas";
import { loadFieldDefsByEntity } from "@/lib/domain/crm-fields";
import { listMessages, sendMessage } from "@/lib/domain/messages";
import { directory } from "@/lib/domain/members";
import { listAgents } from "@/lib/domain/agents";
import { appendAudit } from "@/lib/audit/chain";

export interface ChannelAgentResult {
  ok: boolean;
  reason?: string;
  messageId?: string;
}

const CONTEXT_TURNS = 15;

/**
 * Run `agentMemberSub` (an Agent-role member) against the recent context of `channelId` and
 * post its reply. The caller must already be authorized to post in the channel.
 */
export async function respondInChannelAsAgent(args: {
  workspaceId: string;
  channelId: string;
  agentMemberSub: string;
  invokedBySub: string;
}): Promise<ChannelAgentResult> {
  const { workspaceId, channelId, agentMemberSub, invokedBySub } = args;

  // The agent must be a real, enabled Agent member of this workspace.
  const agents = await listAgents(workspaceId);
  const agent = agents.find((a) => a.memberSub === agentMemberSub);
  if (!agent) return { ok: false, reason: "not_an_agent" };
  if (!agent.enabled || agent.status !== "active") return { ok: false, reason: "agent_paused" };

  const personaId = await personaIdForAgent(workspaceId, agent.id);
  if (!personaId) return { ok: false, reason: "no_persona" };
  const persona = await resolvePersona(workspaceId, personaId);
  if (!persona || !persona.enabled) return { ok: false, reason: "persona_unavailable" };

  let model;
  try {
    model = getInferenceModel({ model: persona.model, useFrontier: persona.preferFrontier });
  } catch {
    return { ok: false, reason: "inference_unavailable" };
  }

  // Build a readable transcript of the recent channel context.
  const [recent, dir] = await Promise.all([
    listMessages(workspaceId, channelId, { limit: CONTEXT_TURNS }),
    directory(workspaceId),
  ]);
  const nameOf = (sub: string) => dir[sub]?.displayName ?? (sub.startsWith("agent:") ? "Agent" : sub.slice(0, 8));
  const transcript = recent
    .filter((m) => m.body && m.body.trim())
    .map((m) => `${nameOf(m.authorSub)}: ${m.body}`)
    .join("\n");

  // Read-only allow-set (drop HITL/mutating tools) — same posture as incognito.
  const allow = new Set(persona.tools);
  for (const t of persona.tools) if (HITL_TOOLS.has(t)) allow.delete(t);

  const system = buildSystemPrompt({
    persona: { name: persona.name, mission: persona.mission, tools: persona.tools, skills: persona.skills },
    overrides: persona.overrides,
    context: { scope: `channel reply in workspace ${workspaceId}` },
  });

  const tools = citrateCommsTools({
    workspaceId,
    invokedBySub,
    personaId,
    threadId: null,
    agentRole: "Agent",
    allow,
    audit: true,
    fieldDefsByEntity: await loadFieldDefsByEntity(workspaceId),
  });

  const maxSteps = Math.max(1, Math.min(persona.maxSteps, Number(process.env.COMMS_AGENT_MAX_STEPS ?? 16)));
  const maxOutputTokens = Math.min(Number(process.env.CITRATE_MAX_OUTPUT_TOKENS ?? 1024), 4096);

  let text = "";
  try {
    const out = await generateText({
      model,
      system,
      prompt:
        `You were @-mentioned in a team channel. Here is the recent conversation:\n\n${transcript}\n\n` +
        `Reply concisely and helpfully as ${persona.name}. Use your read tools if you need facts; cite what you read. ` +
        `Do not propose writes here — if a change is needed, say so and the member can ask you in a direct chat.`,
      tools,
      stopWhen: stepCountIs(maxSteps),
      temperature: persona.temperature,
      maxOutputTokens,
    });
    text = (out.text ?? "").trim();
  } catch (err) {
    console.error("[channel-agent] generate failed:", err);
    return { ok: false, reason: "generation_failed" };
  }
  if (!text) return { ok: false, reason: "empty" };

  const message = await sendMessage({
    workspaceId,
    channelId,
    authorSub: agentMemberSub,
    body: text,
    fromAgent: true,
    threadId: null,
    parentId: null,
    clientMsgId: null,
  });
  await appendAudit({ workspaceId, actorSub: invokedBySub, event: "agent_channel_reply", target: `${agent.id}:${channelId}` });
  return { ok: true, messageId: message.id };
}
