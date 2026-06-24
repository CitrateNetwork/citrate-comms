import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { can, Capability } from "@/lib/rbac/matrix";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";
import { configurablePersonaIds, listConfigGrants } from "@/lib/domain/agent-config";
import { directory } from "@/lib/domain/members";
import { PersonaManager } from "@/components/agents/PersonaManager";

export const dynamic = "force-dynamic";

/** Settings → Agents. Owner/Admin customize personas + delegate config; delegated members
 *  see only the personas they were granted. */
export default async function AgentSettingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/settings`);
  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const isAdmin = can(ctx.role, Capability.ManageWorkspace);
  const grantScope = isAdmin ? { all: true, ids: [] as string[] } : await configurablePersonaIds(ws.id, sub);
  // Reachable by admins OR members who hold at least one config grant.
  if (!isAdmin && !grantScope.all && grantScope.ids.length === 0) notFound();

  let personas = await listPersonas(ws.id);
  if (personas.length === 0 && isAdmin) {
    await seedDefaultPersonas(ws.id, sub);
    personas = await listPersonas(ws.id);
  }
  // Non-admins see only the personas they may configure.
  const visible = isAdmin || grantScope.all ? personas : personas.filter((p) => grantScope.ids.includes(p.id));

  const [grants, dir] = isAdmin
    ? await Promise.all([listConfigGrants(ws.id), directory(ws.id)])
    : [[] as Awaited<ReturnType<typeof listConfigGrants>>, {} as Awaited<ReturnType<typeof directory>>];
  const memberOpts = Object.entries(dir)
    .filter(([, e]) => !e.isAgent)
    .map(([s, e]) => ({ sub: s, name: e.displayName }));

  return (
    <PersonaManager
      workspaceId={ws.id}
      backHref={`/w/${slug}/settings`}
      personas={visible.map((p) => ({ id: p.id, name: p.name, baseTemplate: p.baseTemplate, isTemplate: p.isTemplate, enabled: p.enabled, toolCount: p.tools.length }))}
      canDelegate={isAdmin}
      members={memberOpts}
      grants={grants.map((g) => ({ id: g.id, granteeSub: g.granteeSub, granteeName: g.granteeName, personaId: g.personaId }))}
    />
  );
}
