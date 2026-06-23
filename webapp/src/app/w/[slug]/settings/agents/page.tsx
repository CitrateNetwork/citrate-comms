import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { can, Capability } from "@/lib/rbac/matrix";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";
import { PersonaManager } from "@/components/agents/PersonaManager";

export const dynamic = "force-dynamic";

/** Settings → Agents. Owner/Admin customize personas (prompts, skills, model, tools). */
export default async function AgentSettingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/settings`);
  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  if (!can(ctx.role, Capability.ManageWorkspace)) notFound();

  let personas = await listPersonas(ws.id);
  if (personas.length === 0) {
    await seedDefaultPersonas(ws.id, sub);
    personas = await listPersonas(ws.id);
  }

  return (
    <PersonaManager
      workspaceId={ws.id}
      backHref={`/w/${slug}/settings`}
      personas={personas.map((p) => ({ id: p.id, name: p.name, baseTemplate: p.baseTemplate, isTemplate: p.isTemplate, enabled: p.enabled, toolCount: p.tools.length }))}
    />
  );
}
