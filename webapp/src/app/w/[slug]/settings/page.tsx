import { redirect, notFound } from "next/navigation";
import { sessionOwner } from "@/lib/auth/session";
import { serverSession } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { memberRow } from "@/lib/domain/members";
import { getSettings } from "@/lib/domain/settings";
import { channelsForMember } from "@/lib/domain/channels";
import { can, Capability } from "@/lib/rbac/matrix";
import { SettingsScreen } from "@/components/settings/SettingsScreen";

export const dynamic = "force-dynamic";

export default async function SettingsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const session = await serverSession();
  const sub = sessionOwner(session);
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/settings`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const [me, settings, channels] = await Promise.all([
    memberRow(ws.id, sub),
    getSettings(ws.id),
    channelsForMember(ws.id, sub),
  ]);

  return (
    <SettingsScreen
      workspaceId={ws.id}
      workspaceSlug={slug}
      canManage={can(ctx.role, Capability.ManageWorkspace)}
      identity={{
        displayName: me?.displayName ?? sub.slice(0, 8),
        walletAddress: me?.walletAddress ?? session.walletAddress ?? null,
        email: me?.email ?? session.email ?? null,
        role: ctx.role,
        kycStatus: me?.kycStatus ?? null,
      }}
      settings={settings}
      channels={channels.map((c) => ({ id: c.id, name: c.name }))}
    />
  );
}
