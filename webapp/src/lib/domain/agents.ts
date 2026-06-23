/**
 * Agent repository — agents-as-members. Adding an agent creates a real `members`
 * row (is_agent=true, role Agent → read+post only, never membership) plus an
 * `agents` config row. The agent then participates like any member: seated into
 * channels, shown in rosters with the AGENT marker, auditable.
 *
 * Autonomous responses (reading channel context → model → posting) run through the
 * comms-web-gateway / comms-agent-bridge (Track C). This module owns the agent's
 * IDENTITY and MEMBERSHIP in the trusted tier; it does not fabricate replies.
 */
import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agents, members } from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";

export interface AgentRow {
  id: string;
  memberSub: string;
  name: string;
  purpose: string | null;
  status: string;
  enabled: boolean;
  sponsorSub: string | null;
}

export async function listAgents(workspaceId: string): Promise<AgentRow[]> {
  const rows = await db()
    .select({
      id: agents.id,
      memberSub: agents.memberSub,
      name: agents.name,
      purpose: agents.purpose,
      status: agents.status,
      enabled: agents.enabled,
      sponsorSub: agents.sponsorSub,
    })
    .from(agents)
    .where(eq(agents.workspaceId, workspaceId));
  return rows;
}

/** Create an agent: a member row (role Agent) + an agents config row. */
export async function addAgent(args: {
  workspaceId: string;
  name: string;
  purpose: string | null;
  sponsorSub: string;
}): Promise<AgentRow> {
  const memberSub = `agent:${randomUUID()}`;
  const d = db();
  await d.insert(members).values({
    workspaceId: args.workspaceId,
    sub: memberSub,
    displayName: args.name,
    role: "Agent",
    status: "active",
    isAgent: true,
  });
  const [row] = await d
    .insert(agents)
    .values({
      workspaceId: args.workspaceId,
      memberSub,
      name: args.name.trim(),
      purpose: args.purpose,
      status: "active",
      sponsorSub: args.sponsorSub,
      enabled: true,
    })
    .returning();
  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.sponsorSub, event: "agent_added", target: row!.id });
  return {
    id: row!.id,
    memberSub: row!.memberSub,
    name: row!.name,
    purpose: row!.purpose,
    status: row!.status,
    enabled: row!.enabled,
    sponsorSub: row!.sponsorSub,
  };
}

/** Pause/resume an agent (enabled flag + status). */
export async function setAgentEnabled(workspaceId: string, agentId: string, enabled: boolean, actorSub: string): Promise<void> {
  await db()
    .update(agents)
    .set({ enabled, status: enabled ? "active" : "paused" })
    .where(and(eq(agents.workspaceId, workspaceId), eq(agents.id, agentId)));
  await appendAudit({ workspaceId, actorSub, event: enabled ? "agent_resumed" : "agent_paused", target: agentId });
}
