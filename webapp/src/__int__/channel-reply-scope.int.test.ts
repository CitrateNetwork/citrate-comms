/**
 * Channel agent replies: the audience is re-checked right before posting, and document /
 * calendar reads made for a channel reply are bounded by EVERY seated member's view.
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));

import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, documentChunks, calendarEvents, eventAttendees, channelMembers, members } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel, addChannelMembers } from "@/lib/domain/channels";
import { agentReplyScope, replyScopeStillValid, CHANNEL_REPLY_DENY, channelReplyAllow } from "@/lib/domain/channel-agent";
import { ALL_TOOL_NAMES } from "@/lib/ai/personas";
import { listDocuments } from "@/lib/domain/documents";
import { citrateCommsTools } from "@/lib/ai/tools";
import { encryptField } from "@/lib/security/crypto";
import { run, sub, addMember } from "./helpers";

type T = Record<string, { execute: (a: unknown) => Promise<unknown> }>;
let ws: string, room: string, dm: string, dmDoc: string, wsDoc: string;

beforeAll(async () => {
  ws = (await createWorkspace({ name: `crs ${run}`, ownerSub: sub("own"), ownerWallet: null, ownerEmail: null })).id;
  for (const [n, r] of [["alice", "Member"], ["bob", "Member"], ["mem", "Member"], ["gst", "Guest"], ["late", "Member"]] as const) await addMember(ws, n, r);
  room = (await createChannel({ workspaceId: ws, kind: "channel", name: "int", createdBySub: sub("alice"), memberSubs: [sub("mem")] })).id;
  dm = (await createChannel({ workspaceId: ws, kind: "dm", name: "ab", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
  dmDoc = (await db().insert(documents).values({ workspaceId: ws, channelId: dm, blobUrl: "", name: "comp-plan.txt", mime: "text/plain", uploadedBySub: sub("alice") }).returning())[0]!.id;
  await db().insert(documentChunks).values({ workspaceId: ws, documentId: dmDoc, ord: 0, textEnc: encryptField(ws, "quarterly compensation plan bob") });
  wsDoc = (await db().insert(documents).values({ workspaceId: ws, blobUrl: "", name: "handbook.txt", mime: "text/plain", uploadedBySub: sub("own") }).returning())[0]!.id;
  await db().insert(documentChunks).values({ workspaceId: ws, documentId: wsDoc, ord: 0, textEnc: encryptField(ws, "quarterly handbook policy") });
});

describe("the reply's audience is re-checked right before posting", () => {
  it("a Guest seated mid-run invalidates the scope; an unchanged audience stays valid", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `t-${run}`, createdBySub: sub("alice"), memberSubs: [sub("mem")] })).id;
    const s = await agentReplyScope(ws, ch, "Member");
    expect(s.effectiveInvokerRole).toBe("Member");
    expect(await replyScopeStillValid(ws, ch, "Member", s.audience, s.effectiveInvokerRole)).toBe(true);
    await addChannelMembers(ws, ch, [sub("gst")]);
    expect(await replyScopeStillValid(ws, ch, "Member", s.audience, s.effectiveInvokerRole)).toBe(false);
  });

  it("a new INTERNAL member seated mid-run also invalidates it (the reply was scoped without them)", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `u-${run}`, createdBySub: sub("alice"), memberSubs: [sub("mem")] })).id;
    const s = await agentReplyScope(ws, ch, "Member");
    await addChannelMembers(ws, ch, [sub("late")]);
    expect(await replyScopeStillValid(ws, ch, "Member", s.audience, s.effectiveInvokerRole)).toBe(false);
  });

  it("a seated member whose standing drops mid-run invalidates it; someone leaving does not", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `v-${run}`, createdBySub: sub("alice"), memberSubs: [sub("mem"), sub("bob")] })).id;
    const s = await agentReplyScope(ws, ch, "Member");
    await db().delete(channelMembers).where(and(eq(channelMembers.channelId, ch), eq(channelMembers.sub, sub("bob"))));
    expect(await replyScopeStillValid(ws, ch, "Member", s.audience, s.effectiveInvokerRole)).toBe(true);
    await db().update(members).set({ role: "Guest" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("mem"))));
    try {
      expect(await replyScopeStillValid(ws, ch, "Member", s.audience, s.effectiveInvokerRole)).toBe(false);
    } finally {
      await db().update(members).set({ role: "Member" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("mem"))));
    }
  });
});

describe("channel-reply reads are bounded by every seated member's view", () => {
  const tools = async (who: string, ch: string) => {
    const s = await agentReplyScope(ws, ch, "Member");
    return citrateCommsTools({ workspaceId: ws, invokedBySub: sub(who), agentRole: "Agent", invokerRole: s.effectiveInvokerRole, audience: s.audience, audit: false }) as unknown as T;
  };

  it("documents.list / documents.read omit the invoker's DM file when another seated member can't see it", async () => {
    const t = await tools("alice", room);
    const list = (await t["documents.list"]!.execute({ limit: 50 })) as { documents: { id: string }[] };
    expect(list.documents.map((d) => d.id)).not.toContain(dmDoc);
    expect(list.documents.map((d) => d.id)).toContain(wsDoc);
    const rag = (await t["documents.read"]!.execute({ query: "quarterly", budget: 10 })) as { results: { documentId: string }[] };
    expect(rag.results.map((r) => r.documentId)).not.toContain(dmDoc);
    expect(rag.results.map((r) => r.documentId)).toContain(wsDoc);
  });

  it("…but a room where every member can see it (the DM itself) still returns it", async () => {
    const t = await tools("alice", dm);
    const list = (await t["documents.list"]!.execute({ limit: 50 })) as { documents: { id: string }[] };
    expect(list.documents.map((d) => d.id)).toContain(dmDoc);
  });

  it("outside a channel reply (no audience) the invoker's own view applies", async () => {
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audit: false }) as unknown as T;
    const list = (await t["documents.list"]!.execute({ limit: 50 })) as { documents: { id: string }[] };
    expect(list.documents.map((d) => d.id)).toContain(dmDoc);
  });

  it("an empty audience sees nothing (fail closed)", async () => {
    expect(await listDocuments(ws, [], 50)).toEqual([]);
  });

  it("calendar.read: details only for events whose organizer and attendees are all seated", async () => {
    const start = new Date(Date.now() + 86400_000);
    const mk = async (title: string, by: string, att: string[]) => {
      const [ev] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, title), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub(by), timezone: "UTC" } as never).returning();
      for (const a of att) await db().insert(eventAttendees).values({ workspaceId: ws, eventId: ev!.id, sub: sub(a) } as never);
    };
    await mk(`room sync ${run}`, "alice", ["mem"]);
    await mk(`alice-bob 1:1 ${run}`, "alice", ["bob"]);
    const t = await tools("alice", room);
    const txt = JSON.stringify(await t["calendar.read"]!.execute({}));
    expect(txt).toContain(`room sync ${run}`);
    expect(txt).not.toContain(`alice-bob 1:1 ${run}`);
    expect(txt).toContain("busy");
  });

  it("a channel reply never gets web.search / web.fetch or any HITL tool", () => {
    const allow = channelReplyAllow(ALL_TOOL_NAMES);
    expect([...CHANNEL_REPLY_DENY].sort()).toEqual(["web.fetch", "web.search"]);
    for (const t of ["web.fetch", "web.search", "crm.write", "terminal.exec"]) expect(allow.has(t as never), t).toBe(false);
    for (const t of ["crm.read", "documents.read", "thread.summarize"]) expect(allow.has(t as never), t).toBe(true);
  });
});
