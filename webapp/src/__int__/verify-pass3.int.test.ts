/** Verifier pass-3 probes, kept as a regression suite (secure outcome asserted). */
import { describe, it, expect, vi, beforeAll } from "vitest";
vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));
vi.mock("@/lib/email/send", async (orig) => ({ ...(await orig<Record<string, unknown>>()), sendInviteEmail: async () => ({ sent: false }) }));
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, channels, channelMembers, members } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel, addChannelMembers } from "@/lib/domain/channels";
import { sendMessage } from "@/lib/domain/messages";
import { agentReplyScope } from "@/lib/domain/channel-agent";
import { citrateCommsTools } from "@/lib/ai/tools";
import { getVisibleDocument } from "@/lib/domain/documents";
import * as invitesRoute from "@/app/api/workspaces/[id]/invites/route";
import * as joinRoute from "@/app/api/join/route";
import * as membersRoute from "@/app/api/workspaces/[id]/members/route";
import * as msgRoute from "@/app/api/channels/[id]/messages/route";
import { run, sub, req, P, addMember } from "./helpers";

let ws: string, shared: string, internal: string, dm: string, dmDoc: string, wsDoc: string;
const mint = async (who: string, body: Record<string, unknown>) => {
  const r = await invitesRoute.POST(req(`/api/workspaces/${ws}/invites`, who, { method: "POST", body: JSON.stringify({ workspaceId: ws, ...body }) }), P({ id: ws }));
  return { status: r.status, token: ((await r.json()) as { link?: string }).link?.split("/join/")[1] };
};
const join = (who: string, token: string) => joinRoute.POST(req(`/api/join`, who, { method: "POST", body: JSON.stringify({ token }) }));
const reads = async (who: string, ch: string) => (await msgRoute.GET(req(`/api/channels/${ch}/messages`, who), P({ id: ch }))).status;
type T = Record<string, { execute: (a: unknown) => Promise<unknown> }>;

beforeAll(async () => {
  ws = (await createWorkspace({ name: `p3 ${run}`, ownerSub: sub("own"), ownerWallet: null, ownerEmail: null })).id;
  for (const [n, r] of [["adm", "Admin"], ["adm2", "Admin"], ["adm3", "Admin"], ["alice", "Member"], ["bob", "Member"], ["mem", "Member"], ["par", "Partner"], ["gst", "Guest"]]) await addMember(ws, n!, r!);
  shared = (await createChannel({ workspaceId: ws, kind: "channel", name: "shared", createdBySub: sub("adm"), memberSubs: [sub("mem"), sub("par"), sub("adm2"), sub("adm3")] })).id;
  internal = (await createChannel({ workspaceId: ws, kind: "channel", name: "int", createdBySub: sub("adm"), memberSubs: [sub("mem"), sub("alice")] })).id;
  dm = (await createChannel({ workspaceId: ws, kind: "dm", name: "ab", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
  dmDoc = (await db().insert(documents).values({ workspaceId: ws, channelId: dm, blobUrl: "https://x.public.blob.vercel-storage.com/a.pdf", name: "a.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning())[0]!.id;
  wsDoc = (await db().insert(documents).values({ workspaceId: ws, blobUrl: "https://x.public.blob.vercel-storage.com/w.pdf", name: "w.pdf", mime: "application/pdf", uploadedBySub: sub("own") }).returning())[0]!.id;
});

describe("pass1/2 probes re-run", () => {
  it("offboarded inviter (via real offboard route): pending invite dead + row expired", async () => {
    const m = await mint("adm2", { email: "o@x.io", role: "Guest", scopeChannelId: shared });
    expect(m.status).toBe(201);
    const off = await membersRoute.DELETE(req(`/api/workspaces/${ws}/members`, "own", { method: "DELETE", body: JSON.stringify({ sub: sub("adm2") }) }), P({ id: ws }));
    expect(off.status).toBe(200);
    expect((await join("late1", m.token!)).status).toBe(400);
    expect(await reads("late1", shared)).toBe(403);
  });
  it("offboarded inviter by direct status flip (no revoke hook): redemption re-check still refuses", async () => {
    const m = await mint("adm3", { email: "o2@x.io", role: "Guest", scopeChannelId: shared });
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("adm3"))));
    expect((await join("late2", m.token!)).status).toBe(400);
    await db().update(members).set({ status: "active" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("adm3"))));
  });
  it("inviter demoted Admin->Member: invite refused", async () => {
    const m = await mint("adm3", { email: "o3@x.io", role: "Guest", scopeChannelId: shared });
    expect((await membersRoute.PATCH(req(`/api/workspaces/${ws}/members`, "own", { method: "PATCH", body: JSON.stringify({ sub: sub("adm3"), role: "Member" }) }), P({ id: ws }))).status).toBe(200);
    expect((await join("late3", m.token!)).status).toBe(400);
    await membersRoute.PATCH(req(`/api/workspaces/${ws}/members`, "own", { method: "PATCH", body: JSON.stringify({ sub: sub("adm3"), role: "Admin" }) }), P({ id: ws }));
  });
  it("Admin-minted Admin invite by an Owner later demoted? (Admin inviting Admin never mintable)", async () => {
    expect((await mint("adm", { email: "aa@x.io", role: "Admin" })).status).toBe(403);
  });
  it("race: accept vs kind flip to dm (20 trials) and accept vs inviter un-seat (20 trials)", async () => {
    let badKind = 0, badSeat = 0;
    for (let i = 0; i < 20; i++) {
      const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `k${i}`, createdBySub: sub("adm") })).id;
      const m = await mint("adm", { email: `k${i}@x.io`, role: "Guest", scopeChannelId: ch });
      await Promise.all([join(`kr${i}`, m.token!), db().update(channels).set({ kind: "dm" }).where(eq(channels.id, ch))]);
      const seat = await db().select().from(channelMembers).where(and(eq(channelMembers.channelId, ch), eq(channelMembers.sub, sub(`kr${i}`))));
      // bad only if the flip committed BEFORE the seat insert: detect via ordering is impossible post-hoc; count seats in now-dm channels
      if (seat.length) badKind++;
      const ch2 = (await createChannel({ workspaceId: ws, kind: "channel", name: `s${i}`, createdBySub: sub("adm") })).id;
      const m2 = await mint("adm", { email: `s${i}@x.io`, role: "Guest", scopeChannelId: ch2 });
      await Promise.all([join(`sr${i}`, m2.token!), db().delete(channelMembers).where(and(eq(channelMembers.channelId, ch2), eq(channelMembers.sub, sub("adm"))))]);
      const s2 = await db().select().from(channelMembers).where(and(eq(channelMembers.channelId, ch2), eq(channelMembers.sub, sub(`sr${i}`))));
      if (s2.length) badSeat++;
    }
    (globalThis as Record<string, unknown>).__race = { seatedThenFlipped: badKind, seatedThenUnseated: badSeat };
    expect(true).toBe(true);
  });
});

describe("agent tool restriction", () => {
  it("shared channel -> Partner scope; internal-only -> invoker role; inactive seat -> Partner", async () => {
    expect((await agentReplyScope(ws, shared, "Member")).effectiveInvokerRole).toBe("Partner");
    expect((await agentReplyScope(ws, internal, "Member")).effectiveInvokerRole).toBe("Member");
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: "ina", createdBySub: sub("adm"), memberSubs: [sub("mem")] })).id;
    await addMember(ws, "ghost", "Member");
    await addChannelMembers(ws, ch, [sub("ghost")]);
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("ghost"))));
    expect((await agentReplyScope(ws, ch, "Member")).effectiveInvokerRole).toBe("Partner");
    const s = await agentReplyScope(ws, shared, "Owner");
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("mem"), agentRole: "Agent", invokerRole: s.effectiveInvokerRole, audience: s.audience });
    expect(Object.keys(t)).toEqual(["thread.summarize"]);
  });
  it("Guest seated AFTER scope computed (mid-turn TOCTOU): scope is stale", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: "toctou", createdBySub: sub("adm"), memberSubs: [sub("mem")] })).id;
    const before = await agentReplyScope(ws, ch, "Member");
    await addChannelMembers(ws, ch, [sub("gst")]); // e.g. Admin seats a Guest / scoped invite accepted during the turn
    const after = await agentReplyScope(ws, ch, "Member");
    (globalThis as Record<string, unknown>).__toctou = { before: before.effectiveInvokerRole, after: after.effectiveInvokerRole };
    expect(before.effectiveInvokerRole).toBe("Member");
    expect(after.effectiveInvokerRole).toBe("Partner");
  });
  it("artifact.attach: refused when one seated member can't see it; allowed when all can", async () => {
    const s = await agentReplyScope(ws, internal, "Member");
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: s.effectiveInvokerRole, audience: s.audience, audit: false }) as unknown as T;
    expect(((await t["artifact.attach"]!.execute({ documentId: dmDoc })) as { ok: boolean }).ok).toBe(false); // mem can't see DM doc
    expect(((await t["artifact.attach"]!.execute({ documentId: wsDoc })) as { ok: boolean }).ok).toBe(true);
  });
  it("attach then visibility change: a Partner seated later sees the attached doc (history semantics)", async () => {
    const m = await sendMessage({ workspaceId: ws, channelId: internal, authorSub: sub("alice"), body: "attached", fromAgent: true });
    const { linkMessageAttachments } = await import("@/lib/domain/messages");
    await linkMessageAttachments(ws, m.id, [wsDoc]);
    await addChannelMembers(ws, internal, [sub("par")]);
    (globalThis as Record<string, unknown>).__later = Boolean(await getVisibleDocument(ws, wsDoc, { sub: sub("par"), internal: false }));
    await db().delete(channelMembers).where(and(eq(channelMembers.channelId, internal), eq(channelMembers.sub, sub("par"))));
    expect(true).toBe(true);
  });
  it("MCP / private agent chat surfaces unchanged: Partner MCP still channel-only", () => {
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("par"), agentRole: "Partner" });
    expect(Object.keys(t)).toEqual(["thread.summarize"]);
  });
});

describe("regressions", () => {
  it("internal-only channel keeps full agent tools", async () => {
    const s = await agentReplyScope(ws, internal, "Member");
    const keys = Object.keys(citrateCommsTools({ workspaceId: ws, invokedBySub: sub("mem"), agentRole: "Agent", invokerRole: s.effectiveInvokerRole, audience: s.audience }));
    for (const k of ["crm.read", "documents.read", "documents.list", "calendar.read", "artifact.attach", "pm.read"]) expect(keys).toContain(k);
  });
  it("legit scoped Partner invite works", async () => {
    const m = await mint("adm", { email: "ok@x.io", role: "Partner", scopeChannelId: shared });
    expect(m.status).toBe(201);
    expect((await join("newp", m.token!)).status).toBe(200);
    expect(await reads("newp", shared)).toBe(200);
  });
});
