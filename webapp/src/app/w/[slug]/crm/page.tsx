import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listAccounts, listDeals, listContacts } from "@/lib/domain/crm";
import { seedDefaultCrmFields } from "@/lib/domain/crm-fields";
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

  // Seed the default custom-field defs on first visit (idempotent), so records are rich
  // out of the box. Best-effort — never block the screen.
  await seedDefaultCrmFields(ws.id, sub).catch(() => {});

  const [accounts, deals, contacts] = await Promise.all([listAccounts(ws.id), listDeals(ws.id), listContacts(ws.id)]);

  return (
    <CrmScreen
      workspaceId={ws.id}
      workspaceSlug={slug}
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
      contacts={contacts.map((c) => ({ id: c.id, name: c.name, title: c.title, accountName: c.accountName ?? null }))}
    />
  );
}
