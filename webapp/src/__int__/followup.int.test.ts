/**
 * PBA-R2 follow-up: offboarded/demoted inviters' invites die, and an
 * @-mentioned agent's tools are bounded by the channel's audience.
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));

import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, channelMembers, invites, members } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel } from "@/lib/domain/channels";
import { createInvite, acceptInvite } from "@/lib/domain/invites";
import { offboard, changeRole } from "@/lib/domain/members";
import { agentReplyScope, channelAudience } from "@/lib/domain/channel-agent";
import { citrateCommsTools } from "@/lib/ai/tools";
import { run, sub, addMember } from "./helpers";
import postgres from "postgres";

let ws: string, room: string, internalRoom: string, dm: string, dmDoc: string, wsDoc: string;

beforeAll(async () => {
  ws = (await createWorkspace({ name: `fu ${run}`, ownerSub: sub("own"), ownerWallet: null, ownerEmail: null })).id;
  for (const [n, r] of [["adm", "Admin"], ["adm3", "Admin"], ["mem", "Member"], ["alice", "Member"], ["bob", "Member"], ["par", "Partner"], ["gst", "Guest"]] as const) await addMember(ws, n, r);
  room = (await createChannel({ workspaceId: ws, kind: "channel", name: "shared", createdBySub: sub("adm"), memberSubs: [sub("mem"), sub("par"), sub("adm3")] })).id;
  internalRoom = (await createChannel({ workspaceId: ws, kind: "channel", name: "internal", createdBySub: sub("own"), memberSubs: [sub("mem"), sub("alice")] })).id;
  dm = (await createChannel({ workspaceId: ws, kind: "dm", name: "ab", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
  dmDoc = (await db().insert(documents).values({ workspaceId: ws, channelId: dm, blobUrl: "", name: "dm.txt", mime: "text/plain", uploadedBySub: sub("alice") }).returning())[0]!.id;
  wsDoc = (await db().insert(documents).values({ workspaceId: ws, blobUrl: "", name: "handbook.txt", mime: "text/plain", uploadedBySub: sub("own") }).returning())[0]!.id;
});

describe("invites die with their issuer's standing", () => {
  it("an offboarded inviter's pending scoped invite admits nobody, and offboard revokes it", async () => {
    const inv = await createInvite({ workspaceId: ws, email: `o-${run}@x.io`, role: "Guest", invitedBySub: sub("adm"), scopeChannelId: room });
    await offboard(ws, sub("adm"), sub("own"));
    const [row] = await db().select().from(invites).where(eq(invites.email, `o-${run}@x.io`));
    expect(row!.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
    expect((await acceptInvite({ token: inv.token, sub: sub("late") })).ok).toBe(false);
    expect(await db().select().from(members).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("late"))))).toHaveLength(0);
    expect(await db().select().from(channelMembers).where(eq(channelMembers.sub, sub("late")))).toHaveLength(0);
  });

  it("even if not revoked at offboard (e.g. a row edited directly), redemption re-checks the inviter", async () => {
    const inv = await createInvite({ workspaceId: ws, email: `p-${run}@x.io`, role: "Guest", invitedBySub: sub("adm3") });
    await db().update(members).set({ status: "suspended" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("adm3"))));
    expect((await acceptInvite({ token: inv.token, sub: sub("late2") })).ok).toBe(false);
    await db().update(members).set({ status: "active" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("adm3"))));
  });

  it("a demoted inviter (no AddMember / can't grant the role) can't admit anyone", async () => {
    const i1 = await createInvite({ workspaceId: ws, email: `q-${run}@x.io`, role: "Member", invitedBySub: sub("adm3") });
    await changeRole(ws, sub("adm3"), "Member", sub("own"));
    expect((await acceptInvite({ token: i1.token, sub: sub("late3") })).ok).toBe(false);
    await changeRole(ws, sub("adm3"), "Admin", sub("own"));
    // an Admin may not grant Admin: an invite minted for Admin by an Admin never redeems
    const i2 = await createInvite({ workspaceId: ws, email: `r-${run}@x.io`, role: "Admin", invitedBySub: sub("adm3") });
    expect((await acceptInvite({ token: i2.token, sub: sub("late4") })).ok).toBe(false);
    // and the happy path still works
    const i3 = await createInvite({ workspaceId: ws, email: `s-${run}@x.io`, role: "Member", invitedBySub: sub("adm3") });
    expect(await acceptInvite({ token: i3.token, sub: sub("fine") })).toMatchObject({ ok: true, alreadyMember: false });
  });
});

describe("the redemption re-check is serialized against concurrent channel changes (FOR SHARE)", () => {
  it("an accept that races a kind flip to DM waits for it, re-checks, and does not seat", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `lock-${run}`, createdBySub: sub("own") })).id;
    const inv = await createInvite({ workspaceId: ws, email: `lk-${run}@x.io`, role: "Guest", invitedBySub: sub("own"), scopeChannelId: ch });
    const other = postgres(process.env.DATABASE_URL!, { max: 1, onnotice: () => {} });
    let settled = false;
    let accept!: Promise<{ ok: boolean }>;
    try {
      await other.begin(async (tx) => {
        await tx`SELECT id FROM channels WHERE id = ${ch} FOR UPDATE`; // a writer holds the row
        accept = acceptInvite({ token: inv.token, sub: sub("racer") }).then((r) => ((settled = true), r));
        await new Promise((r) => setTimeout(r, 500));
        expect(settled).toBe(false); // redemption is waiting on the FOR SHARE lock
        await tx`UPDATE channels SET kind = 'dm' WHERE id = ${ch}`;
      });
      await accept;
    } finally {
      await other.end();
    }
    expect(await db().select().from(channelMembers).where(and(eq(channelMembers.channelId, ch), eq(channelMembers.sub, sub("racer"))))).toHaveLength(0);
  });
});

describe("@-mentioned agents are bounded by the channel audience", () => {
  it("a channel with a Partner seated runs the agent with Partner-level tools, whoever invokes", async () => {
    const scope = await agentReplyScope(ws, room, "Member");
    expect(scope.effectiveInvokerRole).toBe("Partner");
    const tools = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("mem"), agentRole: "Agent", invokerRole: scope.effectiveInvokerRole, audience: scope.audience });
    expect(Object.keys(tools)).toEqual(["thread.summarize"]);
    // a Guest seat has the same effect
    const gRoom = (await createChannel({ workspaceId: ws, kind: "channel", name: "g", createdBySub: sub("mem"), memberSubs: [sub("gst")] })).id;
    expect((await agentReplyScope(ws, gRoom, "Owner")).effectiveInvokerRole).toBe("Partner");
  });

  it("an internal-only channel keeps the invoker's role; an inactive seat counts as external", async () => {
    expect((await agentReplyScope(ws, internalRoom, "Member")).effectiveInvokerRole).toBe("Member");
    await addMember(ws, "gone", "Member");
    await db().insert(channelMembers).values({ workspaceId: ws, channelId: internalRoom, sub: sub("gone") });
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("gone"))));
    expect((await channelAudience(ws, internalRoom)).find((a) => a.sub === sub("gone"))!.internal).toBe(false);
    expect((await agentReplyScope(ws, internalRoom, "Member")).effectiveInvokerRole).toBe("Partner");
    await db().delete(channelMembers).where(and(eq(channelMembers.channelId, internalRoom), eq(channelMembers.sub, sub("gone"))));
  });

  it("artifact.attach only attaches a document EVERY audience member can see", async () => {
    const { audience } = await agentReplyScope(ws, internalRoom, "Member");
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audience, audit: false }) as unknown as Record<string, { execute: (a: unknown) => Promise<unknown> }>;
    // alice can see her DM file, but mem (also in this channel) can't -> refused
    expect(await t["artifact.attach"]!.execute({ documentId: dmDoc })).toMatchObject({ ok: false, error: "not_visible_to_channel" });
    // a workspace document every internal member sees -> attached
    expect(await t["artifact.attach"]!.execute({ documentId: wsDoc })).toMatchObject({ ok: true });
    // without an audience (1:1 agent chat) the invoker's own visibility applies
    const solo = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audit: false }) as unknown as Record<string, { execute: (a: unknown) => Promise<unknown> }>;
    expect(await solo["artifact.attach"]!.execute({ documentId: dmDoc })).toMatchObject({ ok: true });
  });
});
