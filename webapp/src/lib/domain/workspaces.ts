/**
 * Workspace repository. A workspace is the multi-tenant boundary (isolated
 * workspaces on one relay — the Slack-org model). The creating user becomes Owner.
 * All other domain repos hang off `workspaceId` and the `requireMembership` guard.
 */
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { members, workspaces } from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";
import type { Role } from "@/lib/rbac/matrix";

export interface WorkspaceSummary {
  id: string;
  slug: string;
  name: string;
  role: Role;
}

/** Slugify a workspace name into a URL-safe, reasonably unique slug. */
function slugify(name: string): string {
  const base = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
  const suffix = Math.abs(hash(name + ":" + base)).toString(36).slice(0, 5);
  return `${base || "workspace"}-${suffix}`;
}

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

/** Workspaces the user is an active member of, with their role. */
export async function workspacesForUser(sub: string): Promise<WorkspaceSummary[]> {
  const rows = await db()
    .select({ id: workspaces.id, slug: workspaces.slug, name: workspaces.name, role: members.role })
    .from(members)
    .innerJoin(workspaces, eq(members.workspaceId, workspaces.id))
    .where(and(eq(members.sub, sub), eq(members.status, "active")));
  return rows.map((r) => ({ ...r, role: r.role as Role }));
}

export interface CreateWorkspaceInput {
  name: string;
  ownerSub: string;
  ownerWallet?: string | null;
  ownerEmail?: string | null;
  ownerDisplayName?: string | null;
}

/** Create a workspace and seat the creator as Owner (one logical operation). */
export async function createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceSummary> {
  const d = db();
  const [ws] = await d
    .insert(workspaces)
    .values({ slug: slugify(input.name), name: input.name.trim(), ownerSub: input.ownerSub })
    .returning({ id: workspaces.id, slug: workspaces.slug, name: workspaces.name });
  const workspace = ws!;

  await d.insert(members).values({
    workspaceId: workspace.id,
    sub: input.ownerSub,
    walletAddress: input.ownerWallet ?? null,
    email: input.ownerEmail ?? null,
    displayName: input.ownerDisplayName ?? null,
    role: "Owner",
    status: "active",
  });

  await appendAudit({ workspaceId: workspace.id, actorSub: input.ownerSub, event: "workspace_created", target: workspace.slug });
  return { ...workspace, role: "Owner" };
}

/** Look up a workspace by slug (used to resolve /w/[slug] routes). */
export async function workspaceBySlug(slug: string): Promise<{ id: string; slug: string; name: string } | null> {
  const [ws] = await db()
    .select({ id: workspaces.id, slug: workspaces.slug, name: workspaces.name })
    .from(workspaces)
    .where(eq(workspaces.slug, slug))
    .limit(1);
  return ws ?? null;
}
