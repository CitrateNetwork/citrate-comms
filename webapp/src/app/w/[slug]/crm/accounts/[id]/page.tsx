import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { can, Capability, isInternalRole } from "@/lib/rbac/matrix";
import { getAccountFile } from "@/lib/domain/crm-file";
import { RecordFile } from "@/components/crm/RecordFile";

export const dynamic = "force-dynamic";

export default async function AccountFilePage({ params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/crm`);
  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  if (!isInternalRole(ctx.role)) notFound(); // PBA-L3c-002: external roles never see workspace data

  const file = await getAccountFile(ws.id, id);
  if (!file) notFound();
  return (
    <RecordFile
      file={file}
      slug={slug}
      workspaceId={ws.id}
      backHref={`/w/${slug}/crm`}
      canEdit={can(ctx.role, Capability.CreateRecord)}
      canManageFields={can(ctx.role, Capability.ManageWorkspace)}
      canDelete={can(ctx.role, Capability.DeleteRecord)}
    />
  );
}
