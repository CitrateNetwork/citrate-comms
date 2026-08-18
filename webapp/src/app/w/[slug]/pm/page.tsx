import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listProjects, listTasks } from "@/lib/domain/pm";
import { directory } from "@/lib/domain/members";
import { can, Capability } from "@/lib/rbac/matrix";
import { PmScreen } from "@/components/pm/PmScreen";

export const dynamic = "force-dynamic";

export default async function PmPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/pm`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const [projects, tasks, dir] = await Promise.all([listProjects(ws.id), listTasks(ws.id), directory(ws.id)]);

  return (
    <PmScreen
      workspaceId={ws.id}
      canEdit={can(ctx.role, Capability.CreateRecord)}
      canDelete={can(ctx.role, Capability.DeleteRecord)}
      projects={projects.map((p) => ({ id: p.id, name: p.name }))}
      members={Object.entries(dir)
        .filter(([, e]) => !e.isAgent)
        .map(([sub, e]) => ({ sub, name: e.displayName }))}
      tasks={tasks.map((t) => ({
        id: t.id,
        column: t.status,
        projectId: t.projectId,
        title: t.title,
        priority: t.priority,
        assigneeSub: t.assigneeSub,
        assigneeName: t.assigneeSub ? dir[t.assigneeSub]?.displayName ?? null : null,
      }))}
    />
  );
}
