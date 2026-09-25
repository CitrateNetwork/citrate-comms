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
import { citrateCommsTools, CHANNEL_REPLY_DENY } from "@/lib/ai/tools";
import { HITL_TOOLS, type ToolName } from "@/lib/ai/personas";
import { resolvePersona, personaIdForAgent } from "@/lib/domain/personas";
import { loadFieldDefsByEntity } from "@/lib/domain/crm-fields";
import { listMessages, sendMessage, linkMessageAttachments, getMessageAttachments } from "@/lib/domain/messages";
import { directory } from "@/lib/domain/members";
import { listAgents } from "@/lib/domain/agents";
import { notifyChannelMentions } from "@/lib/domain/notifications";
import { appendAudit } from "@/lib/audit/chain";
import { isInternalRole, type Role } from "@/lib/rbac/matrix";
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { channelMembers, members } from "@/lib/db/schema";
import type { DocViewer } from "./documents";

/**
 * Everyone who will read an agent reply posted into `channelId`: the seated, ACTIVE
 * workspace members, with whether each is internal (holds ReadWorkspace). A seat whose
 * member row is missing/inactive counts as external (fail closed).
 */
export async function channelAudience(workspaceId: string, channelId: string): Promise<DocViewer[]> {
  const rows = await db()
    .select({ sub: channelMembers.sub, role: members.role, status: members.status, isAgent: members.isAgent })
    .from(channelMembers)
    .leftJoin(members, and(eq(members.workspaceId, channelMembers.workspaceId), eq(members.sub, channelMembers.sub)))
    .where(and(eq(channelMembers.workspaceId, workspaceId), eq(channelMembers.channelId, channelId)));
  return rows.map((r) => {
    const active = r.status === "active" && Boolean(r.role);
    return { sub: r.sub, internal: active && isInternalRole(r.role as Role), agent: active && r.role === "Agent" && r.isAgent === true };
  });
}

/** The tool scope for an agent reply into `channelId`: the audience, and the invoker role
 *  the tools run as (Partner-level if any external member is seated). */
export async function agentReplyScope(workspaceId: string, channelId: string, invokerRole: Role): Promise<{ audience: DocViewer[]; effectiveInvokerRole: Role }> {
  const audience = await channelAudience(workspaceId, channelId);
  return { audience, effectiveInvokerRole: audience.some((a) => !a.internal) ? "Partner" : invokerRole };
}

export { CHANNEL_REPLY_DENY };

/** The allow-set for a channel reply: the persona's tools minus HITL/mutating tools
 *  (read-only posture) and minus the open-web tools (a URL is an exfil path). */
export function channelReplyAllow(personaTools: readonly ToolName[]): Set<ToolName> {
  const allow = new Set(personaTools);
  for (const t of personaTools) if (HITL_TOOLS.has(t) || CHANNEL_REPLY_DENY.includes(t)) allow.delete(t);
  return allow;
}

/**
 * Is a reply scoped for (`before`, `roleBefore`) still safe to post now? True only when
 * the effective role is unchanged and every current reader was already in the audience
 * the tools were scoped for, with the same internal/external standing.
 */
export async function replyScopeStillValid(
  workspaceId: string,
  channelId: string,
  invokerRole: Role,
  before: DocViewer[],
  roleBefore: Role,
): Promise<boolean> {
  const now = await agentReplyScope(workspaceId, channelId, invokerRole);
  if (now.effectiveInvokerRole !== roleBefore) return false;
  const was = new Map(before.map((v) => [v.sub, v.internal]));
  return now.audience.every((v) => was.has(v.sub) && (was.get(v.sub) || !v.internal));
}

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
  /** The invoking human's role — an external Partner/Guest who @-mentions an agent must
   *  not borrow the agent's workspace-wide read (PBA-L3c-002). */
  invokerRole: Role;
}): Promise<ChannelAgentResult> {
  const { workspaceId, channelId, agentMemberSub, invokedBySub, invokerRole } = args;

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

  // Verifier pass 2 (indirect prompt injection / confused deputy): the reply lands in THIS
  // channel, so the tool surface is bounded by the channel's AUDIENCE, not just the
  // invoker. If any Partner/Guest is seated, the agent runs with Partner-level tools
  // (thread.summarize only) — a Partner's injected text can't steer the agent into
  // reading CRM/docs/calendar into a channel the Partner reads. artifact.attach (internal
  // audiences only) additionally requires EVERY seated member to see the document.
  const { audience, effectiveInvokerRole } = await agentReplyScope(workspaceId, channelId, invokerRole);

  const allow = channelReplyAllow(persona.tools);

  // AGT-ART: collect documents the agent attaches during this turn (artifact.attach).
  const artifactIds = new Set<string>();

  const system = buildSystemPrompt({
    persona: { name: persona.name, mission: persona.mission, tools: persona.tools, skills: persona.skills },
    overrides: persona.overrides,
    resources: persona.resources,
    context: { scope: `channel reply in workspace ${workspaceId}` },
  });

  const tools = citrateCommsTools({
    workspaceId,
    invokedBySub,
    personaId,
    threadId: null,
    agentRole: "Agent",
    invokerRole: effectiveInvokerRole,
    audience,
    allow,
    audit: true,
    collectArtifact: (id) => artifactIds.add(id),
    fieldDefsByEntity: await loadFieldDefsByEntity(workspaceId),
  });

  const maxSteps = Math.max(8, Math.min(persona.maxSteps, Number(process.env.COMMS_AGENT_MAX_STEPS ?? 48)));
  const maxOutputTokens = Math.min(Number(process.env.CITRATE_MAX_OUTPUT_TOKENS ?? 4096), 8192);

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

  // The run can take minutes: re-check the audience right before posting. If anyone was
  // seated who wasn't when the tools were scoped (or someone's standing dropped), the
  // reply is dropped — it was produced for a different audience.
  if (!(await replyScopeStillValid(workspaceId, channelId, invokerRole, audience, effectiveInvokerRole))) {
    await appendAudit({ workspaceId, actorSub: invokedBySub, event: "agent_channel_reply_dropped", target: `${agent.id}:${channelId}` });
    return { ok: false, reason: "audience_changed" };
  }

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
  // AGT-ART: link any artifacts the agent attached so they render on its channel message.
  if (artifactIds.size > 0) {
    await linkMessageAttachments(workspaceId, message.id, [...artifactIds]);
    message.attachments = await getMessageAttachments(workspaceId, message.id);
  }
  // MEN-2: if the agent @-mentioned members in its reply, ping them.
  await notifyChannelMentions({ workspaceId, channelId, messageId: message.id, body: text, actorSub: agentMemberSub });
  await appendAudit({ workspaceId, actorSub: invokedBySub, event: "agent_channel_reply", target: `${agent.id}:${channelId}` });
  return { ok: true, messageId: message.id };
}
