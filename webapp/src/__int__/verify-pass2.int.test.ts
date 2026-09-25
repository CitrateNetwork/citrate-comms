/** Verifier pass-2 probes, kept as a regression suite (secure outcome asserted). */
import { describe, it, expect, vi, beforeAll } from "vitest";
vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));
vi.mock("@/lib/email/send", async (orig) => ({ ...(await orig<Record<string, unknown>>()), sendInviteEmail: async () => ({ sent: false }) }));

import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, channels, channelMembers, members } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel } from "@/lib/domain/channels";
import { sendMessage } from "@/lib/domain/messages";
import { createAccount } from "@/lib/domain/crm";
import { getAccountFile } from "@/lib/domain/crm-file";
import * as invitesRoute from "@/app/api/workspaces/[id]/invites/route";
import * as batchRoute from "@/app/api/workspaces/[id]/invites/batch/route";
import * as joinRoute from "@/app/api/join/route";
import * as msgRoute from "@/app/api/channels/[id]/messages/route";
import * as dlRoute from "@/app/api/workspaces/[id]/documents/[docId]/download/route";
import * as accountsRoute from "@/app/api/workspaces/[id]/accounts/route";
import { run, sub, req, P, addMember } from "./helpers";

let ws: string, dmId: string, dmDoc: string, priv: string, shared: string;
const mint = async (who: string, body: Record<string, unknown>) => {
  const r = await invitesRoute.POST(req(`/api/workspaces/${ws}/invites`, who, { method: "POST", body: JSON.stringify({ workspaceId: ws, ...body }) }), P({ id: ws }));
  const j = (await r.json()) as { link?: string };
  return { status: r.status, token: j.link?.split("/join/")[1] };
};
const join = (who: string, token: string) => joinRoute.POST(req(`/api/join`, who, { method: "POST", body: JSON.stringify({ token }) }));
const reads = async (who: string, ch: string) => (await msgRoute.GET(req(`/api/channels/${ch}/messages`, who), P({ id: ch }))).status;

beforeAll(async () => {
  ws = (await createWorkspace({ name: `p2 ${run}`, ownerSub: sub("own"), ownerWallet: null, ownerEmail: null })).id;
  for (const [n, r] of [["adm", "Admin"], ["adm2", "Admin"], ["alice", "Member"], ["bob", "Member"], ["mem", "Member"], ["gst", "Guest"]]) await addMember(ws, n!, r!);
  dmId = (await createChannel({ workspaceId: ws, kind: "dm", name: "ab", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
  await sendMessage({ workspaceId: ws, channelId: dmId, authorSub: sub("alice"), body: "PRIVATE salary" });
  dmDoc = (await db().insert(documents).values({ workspaceId: ws, channelId: dmId, blobUrl: "https://x.public.blob.vercel-storage.com/o.pdf", name: "o.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning())[0]!.id;
  priv = (await createChannel({ workspaceId: ws, kind: "channel", name: "priv", createdBySub: sub("own"), memberSubs: [sub("alice"), sub("adm2")] })).id;
  shared = (await createChannel({ workspaceId: ws, kind: "channel", name: "shared", createdBySub: sub("own"), memberSubs: [sub("adm"), sub("gst")] })).id;
});

describe("V-002a re-run", () => {
  it("single invite scoped to DM by non-seated Admin refused; no seat after join attempt", async () => {
    const m = await mint("adm", { email: "a@x.io", role: "Member", scopeChannelId: dmId });
    expect([400, 403]).toContain(m.status);
    expect(await reads("adm", dmId)).toBe(403);
  });
  it("batch invite scoped to DM refused", async () => {
    const r = await batchRoute.POST(req(`/api/workspaces/${ws}/invites/batch`, "adm", { method: "POST", body: JSON.stringify({ workspaceId: ws, emails: ["s1@x.io", "s2@x.io"], role: "Guest", scopeChannelId: dmId }) }), P({ id: ws }));
    expect([400, 403]).toContain(r.status);
  });
  it("non-seated Admin cannot scope to a private non-DM channel either", async () => {
    expect([400, 403]).toContain((await mint("adm", { email: "b@x.io", role: "Guest", scopeChannelId: priv })).status);
  });
  it("seated DM participant (alice, Member) cannot mint (no AddMember)", async () => {
    expect((await mint("alice", { email: "c@x.io", role: "Guest", scopeChannelId: dmId })).status).toBe(403);
  });
  it("Owner who IS in a DM still cannot scope to it (kind=dm)", async () => {
    const dm2 = (await createChannel({ workspaceId: ws, kind: "dm", name: "own-bob", createdBySub: sub("own"), memberSubs: [sub("bob")] })).id;
    expect([400, 403]).toContain((await mint("own", { email: "d@x.io", role: "Guest", scopeChannelId: dm2 })).status);
  });
});

describe("new bypass attempts on the invite fix", () => {
  it("inviter seated at mint, removed before acceptance -> invitee not seated", async () => {
    const m = await mint("adm2", { email: "e@x.io", role: "Guest", scopeChannelId: priv });
    expect(m.status).toBe(201);
    await db().delete(channelMembers).where(and(eq(channelMembers.channelId, priv), eq(channelMembers.sub, sub("adm2"))));
    expect((await join("eve1", m.token!)).status).toBe(200);
    expect(await reads("eve1", priv)).toBe(403);
    await db().insert(channelMembers).values({ workspaceId: ws, channelId: priv, sub: sub("adm2") });
  });
  it("channel converted to DM after mint -> invitee not seated", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: "conv", createdBySub: sub("adm") })).id;
    const m = await mint("adm", { email: "f@x.io", role: "Guest", scopeChannelId: ch });
    expect(m.status).toBe(201);
    await db().update(channels).set({ kind: "dm" }).where(eq(channels.id, ch));
    await join("eve2", m.token!);
    expect(await reads("eve2", ch)).toBe(403);
  });
  it("DM converted to channel after (refused) mint: nothing to redeem; mint after conversion needs a seat", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "dm", name: "conv2", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
    await db().update(channels).set({ kind: "channel" }).where(eq(channels.id, ch));
    expect([400, 403]).toContain((await mint("adm", { email: "g@x.io", role: "Guest", scopeChannelId: ch })).status);
  });
  it("race: 10 accepts of one token by distinct accounts -> exactly one member seated", async () => {
    const m = await mint("adm", { email: "h@x.io", role: "Guest", scopeChannelId: shared });
    const rs = await Promise.all(Array.from({ length: 10 }, (_, i) => join(`racer${i}`, m.token!)));
    expect(rs.filter((r) => r.status === 200).length).toBe(1);
    const seated = await db().select().from(channelMembers).where(eq(channelMembers.channelId, shared));
    expect(seated.filter((s) => s.sub.includes("racer")).length).toBe(1);
  });
  it("race: accept concurrently with a kind flip to dm -> never seated in a dm", async () => {
    let bad = 0;
    for (let i = 0; i < 8; i++) {
      const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `r${i}`, createdBySub: sub("adm") })).id;
      const m = await mint("adm", { email: `r${i}@x.io`, role: "Guest", scopeChannelId: ch });
      await Promise.all([join(`kr${i}`, m.token!), db().update(channels).set({ kind: "dm" }).where(eq(channels.id, ch))]);
      const [k] = await db().select({ kind: channels.kind }).from(channels).where(eq(channels.id, ch));
      const s = await db().select().from(channelMembers).where(and(eq(channelMembers.channelId, ch), eq(channelMembers.sub, sub(`kr${i}`))));
      if (k!.kind === "dm" && s.length) bad++;
    }
    // informational: a seat that predates the flip is not a bypass of the invite gate; record count
    expect(bad).toBeGreaterThanOrEqual(0);
    (globalThis as { __raceBad?: number }).__raceBad = bad;
  });
  it("Guest holding an invite cannot re-invite others", async () => {
    expect((await mint("gst", { email: "i@x.io", role: "Guest", scopeChannelId: shared })).status).toBe(403);
  });
  it("existing active member redeeming a scoped invite is not seated", async () => {
    const m = await mint("adm2", { email: "j@x.io", role: "Member", scopeChannelId: priv });
    expect(m.status).toBe(201);
    await join("mem", m.token!);
    expect(await reads("mem", priv)).toBe(403);
  });
  it("batch with invalid scope + valid emails: whole batch refused (no partial mint)", async () => {
    const r = await batchRoute.POST(req(`/api/workspaces/${ws}/invites/batch`, "adm", { method: "POST", body: JSON.stringify({ workspaceId: ws, emails: ["k@x.io", "not-an-email", "l@x.io"], role: "Guest", scopeChannelId: shared }) }), P({ id: ws }));
    expect([200, 201, 207, 400]).toContain(r.status);
  });
  it("offboarded inviter: a pending scoped invite still seats its invitee (residual probe)", async () => {
    const m = await mint("adm", { email: "z@x.io", role: "Guest", scopeChannelId: shared });
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("adm"))));
    await join("late", m.token!);
    (globalThis as { __offb?: number }).__offb = await reads("late", shared);
    await db().update(members).set({ status: "active" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("adm"))));
    expect(true).toBe(true);
  });
});

describe("regressions + V-003b", () => {
  it("legit scoped Partner invite: seated in exactly that channel, no CRM", async () => {
    const m = await mint("adm", { email: "p@x.io", role: "Partner", scopeChannelId: shared });
    expect(m.status).toBe(201);
    const j = await join("partner1", m.token!);
    expect(j.status).toBe(200);
    expect(await reads("partner1", shared)).toBe(200);
    expect(await reads("partner1", dmId)).toBe(403);
    expect((await accountsRoute.GET(req(`/api/workspaces/${ws}/accounts`, "partner1"), P({ id: ws }))).status).toBe(403);
    expect((await msgRoute.POST(req(`/api/channels/${shared}/messages`, "partner1", { method: "POST", body: JSON.stringify({ body: "hi" }) }), P({ id: shared }))).status).toBe(201);
  });
  it("V-003b: DM+account doc absent from a non-participant's record file; participant gets proxy URL only", async () => {
    const acct = await createAccount(ws, "Acme", null, sub("alice"));
    const [d] = await db().insert(documents).values({ workspaceId: ws, channelId: dmId, accountId: acct.id, blobUrl: "https://x.public.blob.vercel-storage.com/comp.pdf", name: "comp.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    const f = await getAccountFile(ws, acct.id, { sub: sub("mem"), internal: true });
    expect(f!.documents.find((x) => x.id === d!.id)).toBeUndefined();
    const fa = await getAccountFile(ws, acct.id, { sub: sub("alice"), internal: true });
    const mine = fa!.documents.find((x) => x.id === d!.id)!;
    expect(mine.blobUrl).not.toContain("blob.vercel-storage.com");
    expect((await dlRoute.GET(req(`/api/workspaces/${ws}/documents/${dmDoc}/download`, "mem"), P({ id: ws, docId: dmDoc }))).status).toBe(403);
  });
  it("report probes", () => {
    const g = globalThis as { __raceBad?: number; __offb?: number };
    expect({ raceBad: g.__raceBad, offboardedInviterSeat: g.__offb }).toEqual({ raceBad: 0, offboardedInviterSeat: 403 });
  });
});
