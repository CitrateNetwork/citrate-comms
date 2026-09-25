import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listPersonas } from "@/lib/domain/personas";
import { directory } from "@/lib/domain/members";
import { listWorkspaceThreads } from "@/lib/domain/agent-threads";
import { can, Capability, isInternalRole } from "@/lib/rbac/matrix";
import { AgentHistoryScreen } from "@/components/agents/AgentHistoryScreen";

export const dynamic = "force-dynamic";

/** CH-1: org-wide agent-conversation directory. Owner/Admin see everyone's saved chats;
 *  members see only their own. Incognito chats are never persisted, so they never appear. */
export default async function AgentHistoryPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/agents/history`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  if (!isInternalRole(ctx.role)) notFound(); // PBA-L3c-002: external roles never see workspace data

  const viewAll = can(ctx.role, Capability.ManageWorkspace);
  const [threads, personas, dir] = await Promise.all([
    listWorkspaceThreads(ws.id, sub, { viewAll, limit: 150 }),
    listPersonas(ws.id),
    directory(ws.id),
  ]);

  // Members who have started at least one thread — the invoker filter (admin view only).
  const memberOpts = viewAll
    ? Array.from(new Set(threads.map((t) => t.invokedBySub))).map((s) => ({
        sub: s,
        name: dir[s]?.displayName ?? "Unknown member",
      }))
    : [];

  return (
    <AgentHistoryScreen
      workspaceId={ws.id}
      workspaceSlug={slug}
      viewAll={viewAll}
      threads={threads.map((t) => ({
        id: t.id,
        title: t.title,
        personaId: t.personaId,
        personaName: t.personaName,
        invokedBySub: t.invokedBySub,
        invokedByName: t.invokedByName,
        createdAt: t.createdAt,
      }))}
      personas={personas.map((p) => ({ id: p.id, name: p.name }))}
      members={memberOpts}
    />
  );
}
