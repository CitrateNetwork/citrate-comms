import Link from "next/link";
import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { channelsForMember } from "@/lib/domain/channels";

/**
 * Comms landing. With no channels yet it shows a real, warm empty state (not a
 * mock) guiding the admin to create the first channel; with channels it routes to
 * the most recent. The per-channel message view (stream + composer + witness ledger)
 * is the next P1 slice.
 */
export const dynamic = "force-dynamic";

export default async function CommsIndex({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/comms`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const channels = await channelsForMember(ws.id, sub);
  if (channels.length > 0) redirect(`/w/${slug}/comms/${channels[0]!.id}`);

  const canCreate = ctx.role === "Owner" || ctx.role === "Admin";

  return (
    <div className="empty-state" style={{ margin: "auto", maxWidth: 460, textAlign: "center", padding: "var(--s-8)" }}>
      <div style={{ fontFamily: "var(--font-editorial)", fontStyle: "italic", fontSize: "var(--t-2xl)", color: "var(--fg-1)" }}>
        Welcome to {ws.name}.
      </div>
      <p style={{ color: "var(--fg-2)", marginTop: "var(--s-3)", lineHeight: 1.6 }}>
        This workspace is end-to-end encrypted to your team. Start by creating your first channel — a place
        for a project, a deal, or just the team.
      </p>
      {canCreate ? (
        <Link href={`/w/${slug}/members`} className="btn btn-primary" style={{ marginTop: "var(--s-5)", display: "inline-flex" }}>
          Set up your team
        </Link>
      ) : (
        <p style={{ color: "var(--fg-3)", marginTop: "var(--s-5)", fontSize: "var(--t-sm)" }}>
          An admin will add you to channels shortly.
        </p>
      )}
    </div>
  );
}
