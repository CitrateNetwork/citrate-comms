import { redirect, notFound } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspaceBySlug } from "@/lib/domain/workspaces";
import { membershipOf } from "@/lib/tenant/guard";
import { listEventsInRange } from "@/lib/domain/calendar";
import { directory } from "@/lib/domain/members";
import { can, Capability } from "@/lib/rbac/matrix";
import { CalendarView } from "@/components/calendar/CalendarView";

export const dynamic = "force-dynamic";

export default async function CalendarPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const sub = await serverOwner();
  if (!sub) redirect(`/auth?returnTo=/w/${slug}/calendar`);

  const ws = await workspaceBySlug(slug);
  if (!ws) notFound();
  const ctx = await membershipOf(ws.id, sub);
  if (!ctx) notFound();

  // Initial window: a week back through ~2 months ahead. The client re-fetches as the
  // user navigates months / switches views.
  const now = new Date();
  const from = new Date(now.getTime() - 7 * 86400_000);
  const to = new Date(now.getTime() + 62 * 86400_000);

  const [events, dir] = await Promise.all([listEventsInRange(ws.id, sub, from.toISOString(), to.toISOString()), directory(ws.id)]);

  const members = Object.entries(dir)
    .filter(([, e]) => !e.isAgent)
    .map(([s, e]) => ({ sub: s, name: e.displayName }));
  const nameBySub: Record<string, string> = {};
  for (const [s, e] of Object.entries(dir)) nameBySub[s] = e.displayName;

  return (
    <CalendarView
      workspaceId={ws.id}
      meSub={sub}
      canEdit={can(ctx.role, Capability.CreateRecord)}
      members={members}
      nameBySub={nameBySub}
      initialEvents={events}
      initialFrom={from.toISOString()}
      initialTo={to.toISOString()}
    />
  );
}
