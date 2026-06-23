import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { can, Capability } from "@/lib/rbac/matrix";
import { listPendingApprovals } from "@/lib/domain/approvals";
import { ApprovalsInbox } from "@/components/agents/ApprovalsInbox";

export const dynamic = "force-dynamic";

export default async function ApprovalsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/approvals`);
  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  if (!can(ctx.role, Capability.CreateRecord)) notFound(); // only those who can act on records

  const approvals = await listPendingApprovals(ws.id);
  return <ApprovalsInbox workspaceId={ws.id} approvals={approvals} />;
}
