/**
 * Member repository — the workspace roster and a sub→display directory used to
 * render message authors, role glyphs, and the members screen.
 */
import { and, eq, isNull } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { members, roleAssertions } from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";
import type { Role } from "@/lib/rbac/matrix";

export interface MemberRow {
  sub: string;
  displayName: string;
  walletAddress: string | null;
  email: string | null;
  role: Role;
  status: string;
  isAgent: boolean;
  kycStatus: string | null;
}

function display(r: typeof members.$inferSelect): string {
  if (r.displayName) return r.displayName;
  if (r.email) return r.email.split("@")[0]!;
  if (r.walletAddress) return `${r.walletAddress.slice(0, 6)}…${r.walletAddress.slice(-4)}`;
  return r.sub.slice(0, 8);
}

/** Full roster for a workspace. */
export async function roster(workspaceId: string): Promise<MemberRow[]> {
  const rows = await db().select().from(members).where(eq(members.workspaceId, workspaceId));
  return rows.map((r) => ({
    sub: r.sub,
    displayName: display(r),
    walletAddress: r.walletAddress,
    email: r.email,
    role: r.role as Role,
    status: r.status,
    isAgent: r.isAgent,
    kycStatus: r.kycStatus,
  }));
}

export interface DirectoryEntry {
  displayName: string;
  role: Role;
  isAgent: boolean;
}

/** sub → {displayName, role, isAgent} for rendering authors without N queries. */
export async function directory(workspaceId: string): Promise<Record<string, DirectoryEntry>> {
  const rows = await roster(workspaceId);
  const map: Record<string, DirectoryEntry> = {};
  for (const m of rows) map[m.sub] = { displayName: m.displayName, role: m.role, isAgent: m.isAgent };
  return map;
}

/**
 * Change a member's role. Records a signed-by-server RoleAssertion (signature null
 * in the trusted tier) and audits the change. The caller's authority to grant the
 * target role (anti-escalation) is checked at the API layer via canGrant.
 */
export async function changeRole(workspaceId: string, subjectSub: string, role: Role, issuerSub: string): Promise<void> {
  const d = db();
  await d
    .update(members)
    .set({ role })
    .where(and(eq(members.workspaceId, workspaceId), eq(members.sub, subjectSub)));
  await d.insert(roleAssertions).values({ workspaceId, subjectSub, role, issuerSub });
  await appendAudit({ workspaceId, actorSub: issuerSub, event: "role_changed", target: `${subjectSub}:${role}` });
}

/**
 * Offboard a member: flip status → offboarded AND revoke their outstanding role
 * assertions in one operation (mirrors the native atomic offboard — role + access
 * revoked together, no window where one outlives the other). Forward-only: their
 * existing data is untouched; they simply lose future access.
 */
export async function offboard(workspaceId: string, subjectSub: string, actorSub: string): Promise<void> {
  const d = db();
  await d
    .update(members)
    .set({ status: "offboarded" })
    .where(and(eq(members.workspaceId, workspaceId), eq(members.sub, subjectSub)));
  await d
    .update(roleAssertions)
    .set({ revokedAt: new Date() })
    .where(and(eq(roleAssertions.workspaceId, workspaceId), eq(roleAssertions.subjectSub, subjectSub), isNull(roleAssertions.revokedAt)));
  await appendAudit({ workspaceId, actorSub, event: "member_offboarded", target: subjectSub });
}

/** A single member's role/status in a workspace, or null. */
export async function memberRow(workspaceId: string, sub: string): Promise<MemberRow | null> {
  const [r] = await db()
    .select()
    .from(members)
    .where(and(eq(members.workspaceId, workspaceId), eq(members.sub, sub)))
    .limit(1);
  if (!r) return null;
  return {
    sub: r.sub,
    displayName: display(r),
    walletAddress: r.walletAddress,
    email: r.email,
    role: r.role as Role,
    status: r.status,
    isAgent: r.isAgent,
    kycStatus: r.kycStatus,
  };
}
