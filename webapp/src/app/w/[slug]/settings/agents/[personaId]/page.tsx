import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { getPersonaConfig } from "@/lib/domain/personas";
import { canConfigurePersona } from "@/lib/domain/agent-config";
import { PersonaEditor } from "@/components/agents/PersonaEditor";

export const dynamic = "force-dynamic";

export default async function PersonaEditorPage({ params }: { params: Promise<{ slug: string; personaId: string }> }) {
  const { slug, personaId } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/settings`);
  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  // Admin OR a member with a config grant for this persona (CFG delegation).
  if (!(await canConfigurePersona(ws.id, sub, ctx.role, personaId))) notFound();

  const config = await getPersonaConfig(ws.id, personaId);
  if (!config) notFound();

  return <PersonaEditor workspaceId={ws.id} backHref={`/w/${slug}/settings/agents`} config={config} />;
}
