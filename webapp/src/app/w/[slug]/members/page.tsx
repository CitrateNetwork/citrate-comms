import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { roster } from "@/lib/domain/members";
import { listPendingInvites } from "@/lib/domain/invites";
import { can, Capability } from "@/lib/rbac/matrix";
import { MembersScreen } from "@/components/members/MembersScreen";

/**
 * Members & onboarding screen. Owners/Admins manage the roster, invite by email,
 * change roles, and offboard. Members/Partners/Guests see the roster read-only.
 */
export const dynamic = "force-dynamic";

export default async function MembersPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/members`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const canManage = can(ctx.role, Capability.AddMember);
  const [members, pending] = await Promise.all([
    roster(ws.id),
    canManage ? listPendingInvites(ws.id) : Promise.resolve([]),
  ]);

  return (
    <MembersScreen
      workspaceId={ws.id}
      myRole={ctx.role}
      mySub={sub}
      canManage={canManage}
      members={members.map((m) => ({
        sub: m.sub,
        displayName: m.displayName,
        walletAddress: m.walletAddress,
        email: m.email,
        role: m.role,
        status: m.status,
        isAgent: m.isAgent,
        kycStatus: m.kycStatus,
      }))}
      pending={pending}
    />
  );
}
