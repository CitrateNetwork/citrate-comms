import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { can, Capability } from "@/lib/rbac/matrix";
import { ImportsPanel } from "@/components/crm/ImportsPanel";

export const dynamic = "force-dynamic";

/** Data imports: drop spreadsheets, map columns, and bulk-import into the CRM. */
export default async function ImportsPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/crm/imports`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();
  const canEdit = can(ctx.role, Capability.CreateRecord);

  return (
    <div style={{ padding: "var(--s-5)", display: "flex", flexDirection: "column", gap: "var(--s-5)" }}>
      <div>
        <h1 style={{ margin: 0, fontSize: "1.4rem" }}>Data imports</h1>
        <p style={{ color: "var(--fg-3)", fontSize: "var(--t-sm)", marginTop: "var(--s-2)", maxWidth: 640 }}>
          Drop any number of spreadsheets (xlsx / csv). Each becomes a structured table you can map
          into accounts, contacts, deals and tasks, then bulk-import — deduped, with emails and phones
          kept encrypted. Large files import in batches and resume on their own.
        </p>
      </div>

      <ImportsPanel workspaceId={ws.id} canEdit={canEdit} />
    </div>
  );
}
