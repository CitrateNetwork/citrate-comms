import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listAudit, verifyChainFromDb } from "@/lib/audit/chain";
import { directory } from "@/lib/domain/members";
import { AuditScreen } from "@/components/admin-audit/AuditScreen";

export const dynamic = "force-dynamic";

export default async function AuditPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/audit`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const [records, integrity, dir] = await Promise.all([
    listAudit(ws.id),
    verifyChainFromDb(ws.id),
    directory(ws.id),
  ]);

  const nameMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(dir)) nameMap[k] = v.displayName;

  return (
    <AuditScreen
      workspaceId={ws.id}
      records={records}
      initialIntegrity={integrity}
      directory={nameMap}
    />
  );
}
