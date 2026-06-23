import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";
import { AgentChat } from "@/components/agents/AgentChat";

export const dynamic = "force-dynamic";

/**
 * Persona chat page — `[id]` is the persona (the agent BRAIN) you're chatting with.
 * Seeds the default templates on first visit so there's always someone to talk to.
 */
export default async function AgentChatPage({ params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/agents`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  let personas = await listPersonas(ws.id);
  if (personas.length === 0) {
    await seedDefaultPersonas(ws.id, sub);
    personas = await listPersonas(ws.id);
  }
  const persona = personas.find((p) => p.id === id);
  if (!persona) notFound();

  return (
    <AgentChat
      workspaceId={ws.id}
      slug={slug}
      persona={{ id: persona.id, name: persona.name, key: persona.key, tools: persona.tools }}
      personas={personas.map((p) => ({ id: p.id, name: p.name, key: p.key }))}
    />
  );
}
