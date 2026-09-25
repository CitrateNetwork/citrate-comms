/**
 * Tenant + RBAC guard — the single gauntlet every workspace-scoped route/action
 * runs. This is where the trusted-tier app earns its keep: the CLIENT only hides
 * affordances; authorization is decided HERE, server-side, on every mutation.
 *
 * Gauntlet:
 *   requireOwner(req)                  → sub | 401            (verifySession, fail-closed)
 *   requireMembership(workspaceId,sub) → MemberCtx | 403      (tenant isolation)
 *   assertCan(ctx, Capability)         → throws GuardError(403) if role lacks cap
 *
 * Every query against a workspace-scoped table MUST be predicated on workspaceId
 * AFTER requireMembership confirms the caller belongs. A custom semgrep rule
 * (.semgrep/) enforces the predicate; this guard is the runtime half.
 */
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { members } from "@/lib/db/schema";
import { requireOwner } from "@/lib/auth";
import { Capability, can, type Role } from "@/lib/rbac/matrix";

export class GuardError extends Error {
  constructor(public status: 401 | 403, message: string) {
    super(message);
    this.name = "GuardError";
  }
}

export interface MemberCtx {
  workspaceId: string;
  sub: string;
  role: Role;
  isAgent: boolean;
}

/** Identify the caller or throw 401. */
export async function requireSub(req: Request): Promise<string> {
  const sub = await requireOwner(req);
  if (!sub) throw new GuardError(401, "unauthenticated");
  return sub;
}

/**
 * Confirm the caller is an active member of the workspace and return their role.
 * Offboarded/suspended/invited members are NOT active and are rejected (403).
 */
export async function requireMembership(workspaceId: string, sub: string): Promise<MemberCtx> {
  const [m] = await db()
    .select({ role: members.role, status: members.status, isAgent: members.isAgent })
    .from(members)
    .where(and(eq(members.workspaceId, workspaceId), eq(members.sub, sub)))
    .limit(1);
  if (!m || m.status !== "active") throw new GuardError(403, "not a member of this workspace");
  return { workspaceId, sub, role: m.role as Role, isAgent: m.isAgent };
}

/** Resolve the caller end-to-end (auth + membership) in one call. */
export async function requireMember(req: Request, workspaceId: string): Promise<MemberCtx> {
  const sub = await requireSub(req);
  return requireMembership(workspaceId, sub);
}

/**
 * Non-throwing membership lookup for server components/layouts that prefer to
 * `redirect()` rather than throw. Returns the active member context or null.
 */
export async function membershipOf(workspaceId: string, sub: string): Promise<MemberCtx | null> {
  try {
    return await requireMembership(workspaceId, sub);
  } catch {
    return null;
  }
}

/** Throw 403 unless the member's role holds the capability. */
export function assertCan(ctx: MemberCtx, cap: Capability): void {
  if (!can(ctx.role, cap)) {
    throw new GuardError(403, `role ${ctx.role} lacks capability ${cap}`);
  }
}

/** Convenience: require membership AND a capability. */
export async function requireCapability(
  req: Request,
  workspaceId: string,
  cap: Capability,
): Promise<MemberCtx> {
  const ctx = await requireMember(req, workspaceId);
  assertCan(ctx, cap);
  return ctx;
}

/**
 * Workspace-level data gate (PBA-L3c-002): membership AND `ReadWorkspace`, which only
 * the internal roles hold. Every non-channel workspace read (CRM, calendar, documents,
 * tables, PM, personas, agents, MCP data tools) runs this — Partner/Guest are external
 * and see only the channels they are seated in. Deny by default: a new workspace route
 * that forgets this is caught by the route x role matrix test (rbac-routes.int.test.ts).
 */
export async function requireInternal(req: Request, workspaceId: string): Promise<MemberCtx> {
  return requireCapability(req, workspaceId, Capability.ReadWorkspace);
}

/**
 * Channel-scoped guard for `/api/channels/[id]/*` routes. Resolves the channel's
 * workspace, runs the workspace membership + capability check, then confirms the
 * caller is a member of THIS channel (scoping for Partner/Guest, and the natural
 * boundary for everyone). Returns the member context + the resolved workspaceId.
 */
export async function requireChannel(
  req: Request,
  channelId: string,
  cap: Capability,
  resolveWorkspace: (channelId: string) => Promise<string | null>,
  isMember: (channelId: string, sub: string) => Promise<boolean>,
): Promise<MemberCtx> {
  const workspaceId = await resolveWorkspace(channelId);
  if (!workspaceId) throw new GuardError(403, "channel not found");
  const ctx = await requireMember(req, workspaceId);
  assertCan(ctx, cap);
  if (!(await isMember(channelId, ctx.sub))) throw new GuardError(403, "not a member of this channel");
  return ctx;
}

export { Capability };
