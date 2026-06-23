import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listAccounts, listDeals } from "@/lib/domain/crm";
import { can, Capability } from "@/lib/rbac/matrix";
import { CrmScreen } from "@/components/crm/CrmScreen";

export const dynamic = "force-dynamic";

export default async function CrmPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/crm`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const [accounts, deals] = await Promise.all([listAccounts(ws.id), listDeals(ws.id)]);

  return (
    <CrmScreen
      workspaceId={ws.id}
      canEdit={can(ctx.role, Capability.CreateRecord)}
      accounts={accounts.map((a) => ({ id: a.id, name: a.name, domain: a.domain }))}
      deals={deals.map((d) => ({
        id: d.id,
        column: d.stage,
        accountId: d.accountId,
        accountName: d.accountName,
        name: d.name,
        valueMinor: d.valueMinor,
      }))}
    />
  );
}
