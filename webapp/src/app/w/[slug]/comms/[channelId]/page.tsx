import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { channelById, isChannelMember } from "@/lib/domain/channels";
import { listMessages } from "@/lib/domain/messages";
import { listLedger } from "@/lib/witness/ledger";
import { directory } from "@/lib/domain/members";
import { can, Capability } from "@/lib/rbac/matrix";
import { ChannelView } from "@/components/comms/ChannelView";

/**
 * Per-channel comms screen. Guards: authenticated → workspace member → channel
 * member. Loads the (decrypted, trusted-tier) message stream, the witness ledger,
 * and the author directory, then hands them to the interactive client view.
 */
export const dynamic = "force-dynamic";

export default async function ChannelPage({
  params,
}: {
  params: Promise<{ slug: string; channelId: string }>;
}) {
  const { slug, channelId } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/comms/${channelId}`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  const channel = await channelById(ws.id, channelId);
  if (!channel || !(await isChannelMember(channelId, sub))) notFound();

  const [messages, ledger, dir] = await Promise.all([
    listMessages(ws.id, channelId, { limit: 200 }),
    listLedger(ws.id, channelId),
    directory(ws.id),
  ]);

  return (
    <ChannelView
      channelId={channelId}
      channelName={channel.name}
      topic={channel.topic}
      mySub={sub}
      canPost={can(ctx.role, Capability.PostMessage)}
      initialMessages={messages.map((m) => ({
        id: m.id,
        authorSub: m.authorSub,
        fromAgent: m.fromAgent,
        body: m.body,
        seq: m.seq,
        onBehalfOf: m.onBehalfOf,
        createdAt: m.createdAt,
      }))}
      initialLedger={ledger.map((e) => ({
        id: e.id,
        kind: e.kind,
        text: e.text,
        bySub: e.bySub,
        status: e.status,
        createdAt: e.createdAt,
      }))}
      directory={dir}
    />
  );
}
