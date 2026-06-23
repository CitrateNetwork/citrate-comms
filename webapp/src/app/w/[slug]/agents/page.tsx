import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listAgents } from "@/lib/domain/agents";
import { channelsForMember } from "@/lib/domain/channels";
import { directory } from "@/lib/domain/members";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";
import { can, Capability } from "@/lib/rbac/matrix";
import { AgentsScreen } from "@/components/agents/AgentsScreen";

export const dynamic = "force-dynamic";

export default async function AgentsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/agents`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const [agents, channels, dir] = await Promise.all([
    listAgents(ws.id),
    channelsForMember(ws.id, sub),
    directory(ws.id),
  ]);

  // The agent BRAINS (personas) — seed the org defaults on first visit.
  let personas = await listPersonas(ws.id);
  if (personas.length === 0) {
    await seedDefaultPersonas(ws.id, sub);
    personas = await listPersonas(ws.id);
  }

  return (
    <AgentsScreen
      workspaceId={ws.id}
      workspaceSlug={slug}
      canManage={can(ctx.role, Capability.AddAgent)}
      canCustomize={can(ctx.role, Capability.ManageWorkspace)}
      personas={personas.map((p) => ({ id: p.id, name: p.name, key: p.key, baseTemplate: p.baseTemplate, toolCount: p.tools.length }))}
      agents={agents.map((a) => ({
        id: a.id,
        memberSub: a.memberSub,
        name: a.name,
        purpose: a.purpose,
        status: a.status,
        enabled: a.enabled,
        sponsorName: a.sponsorSub ? dir[a.sponsorSub]?.displayName ?? null : null,
      }))}
      channels={channels.map((c) => ({ id: c.id, name: c.name }))}
    />
  );
}
