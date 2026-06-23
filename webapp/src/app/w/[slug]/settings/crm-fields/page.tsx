import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { can, Capability } from "@/lib/rbac/matrix";
import { listFieldDefs } from "@/lib/domain/crm-fields";
import { CRM_ENTITIES } from "@/lib/domain/crm-enums";
import { CrmFieldsManager, type ManagerFields } from "@/components/crm/CrmFieldsManager";

export const dynamic = "force-dynamic";

/** Settings → CRM fields. Owner/Admin define the custom-field engine per entity. */
export default async function CrmFieldsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/settings`);
  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  if (!can(ctx.role, Capability.ManageWorkspace)) notFound(); // admin-only surface

  const fields = {} as ManagerFields;
  for (const e of CRM_ENTITIES) fields[e] = await listFieldDefs(ws.id, e, { includeDisabled: true });

  return <CrmFieldsManager workspaceId={ws.id} backHref={`/w/${slug}/settings`} fields={fields} />;
}
