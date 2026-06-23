import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { channelsForMember } from "@/lib/domain/channels";
import { can, Capability } from "@/lib/rbac/matrix";
import { AppShell, type SpaceLink } from "@/components/shell/AppShell";

/**
 * Workspace shell layout. Guards: authenticated → workspace exists → caller is an
 * active member (else 404, not "forbidden" — don't leak workspace existence). Loads
 * the caller's channels for the rail. Every child page renders inside this shell.
 */
export const dynamic = "force-dynamic";

export default async function WorkspaceLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/comms`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();

  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound(); // not a member — do not reveal the workspace

  const channels = await channelsForMember(ws.id, sub);
  const spaces: SpaceLink[] = channels.map((c) => ({ id: c.id, name: c.name, kind: c.kind, hasAgent: c.hasAgent }));

  return (
    <AppShell
      workspaceId={ws.id}
      workspaceSlug={slug}
      workspaceName={ws.name}
      role={ctx.role}
      meSub={sub}
      canCreateChannel={can(ctx.role, Capability.CreateChannel)}
      canCreateDm={can(ctx.role, Capability.CreateDirectMessage)}
      spaces={spaces}
    >
      {children}
    </AppShell>
  );
}
