/**
 * The agentic-loop chat route (COMMS-AGENTS overview §3) — the citrate-explorer
 * pattern, adapted for the trusted-tier comms CRM. Streams a persona turn:
 *
 *   auth + RBAC → rate-limit → resolve persona → layered system prompt →
 *   streamText(tools, stepCountIs budget, temperature) → persist thread + audit →
 *   error-scrubbed UI message stream.
 *
 * `[agentId]` is the PERSONA id you are chatting with (the agent BRAIN). The invoking
 * human must hold PostMessage; the persona acts as a role=Agent member (read/post/
 * propose — never membership). Every tool call is audited() inside the registry, and
 * writes/terminal are HITL-gated (later sprints). The SAME tool registry is exposed
 * at `/api/workspaces/[id]/mcp` — single source of truth, no drift.
 */
import { streamText, convertToModelMessages, stepCountIs, type UIMessage } from "ai";
import { Capability, requireMember, assertCan } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { getInferenceModel } from "@/lib/ai/provider";
import { buildSystemPrompt } from "@/lib/ai/system-prompt";
import { citrateCommsTools } from "@/lib/ai/tools";
import { HITL_TOOLS } from "@/lib/ai/personas";
import { resolvePersona } from "@/lib/domain/personas";
import { loadFieldDefsByEntity } from "@/lib/domain/crm-fields";
import { getOrCreateThread, appendAgentMessage } from "@/lib/domain/agent-threads";

export const runtime = "nodejs";
export const maxDuration = 300;

function uiText(m?: UIMessage): string {
  const parts = (m as { parts?: { type: string; text?: string }[] } | undefined)?.parts;
  if (!Array.isArray(parts)) return "";
  return parts
    .filter((p) => p.type === "text" && typeof p.text === "string")
    .map((p) => p.text as string)
    .join(" ")
    .trim();
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string; agentId: string }> }) {
  let workspaceId: string;
  let personaId: string;
  let sub: string;
  try {
    const p = await params;
    workspaceId = p.id;
    personaId = p.agentId;
    // Auth + membership; the invoking human must be able to post.
    const ctx = await requireMember(req, workspaceId);
    assertCan(ctx, Capability.PostMessage);
    sub = ctx.sub;
  } catch (e) {
    return errorResponse(e);
  }

  // Inference + tools cost money — rate-limit per user (fail-closed, WEB-1).
  const rl = await limit(`agent-chat:${hashId(sub)}`);
  if (!rl.success) return Response.json({ error: "Too many requests — slow down a moment." }, { status: 429 });

  // Resolve the persona (workspace-scoped). Disabled/unknown → refuse.
  const persona = await resolvePersona(workspaceId, personaId);
  if (!persona || !persona.enabled) return Response.json({ error: "persona_not_found" }, { status: 404 });

  let body: { messages?: UIMessage[]; threadId?: string; incognito?: boolean };
  try {
    body = (await req.json()) as { messages?: UIMessage[]; threadId?: string; incognito?: boolean };
  } catch {
    return Response.json({ error: "bad_request" }, { status: 400 });
  }
  const messages = Array.isArray(body.messages) ? body.messages : [];
  if (messages.length === 0) return Response.json({ error: "no_messages" }, { status: 400 });

  // CH-2: incognito = private, session-only. No thread/message persistence, no audit, and
  // read-only tools (no writes ⇒ nothing that must be logged), so it leaves no trace.
  const incognito = body.incognito === true;

  // Inference model (gateway, or the persona's frontier route when enabled).
  let model;
  try {
    model = getInferenceModel({ model: persona.model, useFrontier: persona.preferFrontier });
  } catch (err) {
    console.error("[agent/chat] inference unavailable:", err);
    return Response.json({ error: "Inference is not available right now." }, { status: 503 });
  }

  // Persist the thread + the user turn (best-effort) — skipped entirely in incognito.
  const lastUser = uiText(messages[messages.length - 1]);
  const threadId = incognito
    ? null
    : await getOrCreateThread({
        workspaceId,
        personaId,
        invokedBySub: sub,
        title: lastUser ? lastUser.slice(0, 80) : `Chat with ${persona.name}`,
        threadId: body.threadId,
      });
  if (!incognito) {
    if (threadId && lastUser) await appendAgentMessage({ workspaceId, threadId, role: "user", content: lastUser });
    await appendAudit({ workspaceId, actorSub: sub, event: "agent_invoked", target: `${persona.key}:${threadId ?? ""}` });
  }

  // Budget ceilings (S6 hardening): hard caps so a mis-set/customized persona can't run
  // away — clamped regardless of the persona's configured values.
  const historyTurns = Math.min(Number(process.env.CITRATE_HISTORY_TURNS ?? 8), 20);
  // Output budget: 1024 was truncating multi-step answers mid-stream. Default 4096, ceiling 8192.
  const maxOutputTokens = Math.min(Number(process.env.CITRATE_MAX_OUTPUT_TOKENS ?? 4096), 8192);
  // Tool-step budget: batch work (e.g. create N accounts + N deals) needs many tool calls.
  // Floor of 8 so a conservatively-tuned persona still gets enough steps to finish a turn.
  const stepCeiling = Number(process.env.COMMS_AGENT_MAX_STEPS ?? 48);
  const maxSteps = Math.max(8, Math.min(persona.maxSteps, stepCeiling));

  const system = buildSystemPrompt({
    persona: { name: persona.name, mission: persona.mission, tools: persona.tools, skills: persona.skills },
    overrides: persona.overrides,
    resources: persona.resources,
    context: { scope: `workspace ${workspaceId}` },
  });

  // Incognito ⇒ read-only tools (drop every HITL/mutating tool) so nothing needs auditing.
  const allow = new Set(persona.tools);
  if (incognito) for (const t of persona.tools) if (HITL_TOOLS.has(t)) allow.delete(t);

  const tools = citrateCommsTools({
    workspaceId,
    invokedBySub: sub,
    personaId,
    threadId,
    agentRole: "Agent",
    allow,
    audit: !incognito,
    fieldDefsByEntity: await loadFieldDefsByEntity(workspaceId),
  });

  const result = streamText({
    model,
    system,
    messages: await convertToModelMessages(messages.slice(-historyTurns)),
    tools,
    stopWhen: stepCountIs(maxSteps),
    temperature: persona.temperature,
    maxOutputTokens,
    onFinish: async ({ text }) => {
      if (threadId && text) await appendAgentMessage({ workspaceId, threadId, role: "assistant", content: text });
    },
  });

  return result.toUIMessageStreamResponse({
    headers: threadId ? { "x-thread-id": threadId } : undefined,
    onError: (error) => {
      // FUA-EXPLORER-05: full error server-side, generic message to the client.
      console.error("[agent/chat] stream error:", error);
      return "The agent hit an error while processing this request. Please try again.";
    },
  });
}
