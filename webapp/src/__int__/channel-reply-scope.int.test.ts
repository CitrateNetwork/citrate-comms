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
import { ALL_TOOL_NAMES, HITL_TOOLS } from "@/lib/ai/personas";
import { listDocuments } from "@/lib/domain/documents";
import { listMessages, sendMessage } from "@/lib/domain/messages";
import { postAndPinCalendarSummary, everyReaderParticipates } from "@/lib/domain/calendar";
import { citrateCommsTools } from "@/lib/ai/tools";
import { encryptField } from "@/lib/security/crypto";
import { run, sub, addMember } from "./helpers";

type T = Record<string, { execute: (a: unknown) => Promise<unknown> }>;
const tools = async (who: string, ch: string) => {
  const s = await agentReplyScope(ws, ch, "Member");
  return citrateCommsTools({ workspaceId: ws, invokedBySub: sub(who), agentRole: "Agent", invokerRole: s.effectiveInvokerRole, audience: s.audience, audit: false }) as unknown as T;
};
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

  it("a channel reply never gets web.search / web.fetch or any HIC tool", () => {
    const allow = channelReplyAllow(ALL_TOOL_NAMES);
    expect([...CHANNEL_REPLY_DENY].sort()).toEqual(["web.fetch", "web.search"]);
    for (const t of ["web.fetch", "web.search", "crm.write", "terminal.exec"]) expect(allow.has(t as never), t).toBe(false);
    for (const t of ["crm.read", "documents.read", "thread.summarize"]) expect(allow.has(t as never), t).toBe(true);
  });
});

describe("pass-4: invoker visibility AND whole-audience participation", () => {
  it("calendar.read in a channel reply: a non-attendee invoker never gets another pair's event details", async () => {
    const big = (await createChannel({ workspaceId: ws, kind: "channel", name: `gen-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob"), sub("mem")] })).id;
    const start = new Date(Date.now() + 2 * 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, `pair review ${run}`), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: ws, eventId: ev!.id, sub: sub("bob") } as never);
    for (const who of ["mem", "alice"]) {
      const t = await tools(who, big);
      expect(JSON.stringify(await t["calendar.read"]!.execute({})), who).not.toContain(`pair review ${run}`);
    }
    // an all-hands event (every seated member participates) seen by a participant invoker is detailed
    const [all] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, `all hands ${run}`), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    for (const a of ["bob", "mem"]) await db().insert(eventAttendees).values({ workspaceId: ws, eventId: all!.id, sub: sub(a) } as never);
    expect(JSON.stringify(await (await tools("mem", big))["calendar.read"]!.execute({}))).toContain(`all hands ${run}`);
  });

  it("everyReaderParticipates: every reader must be organizer or attendee; empty audience -> false", () => {
    const ev = { createdBySub: "a", attendees: [{ sub: "b" }] } as never;
    expect(everyReaderParticipates(ev, ["a", "b"])).toBe(true);
    expect(everyReaderParticipates(ev, ["a"])).toBe(true);
    expect(everyReaderParticipates(ev, ["a", "b", "c"])).toBe(false);
    expect(everyReaderParticipates(ev, [])).toBe(false);
  });

  it("calendar.pin_summary never pins an event some seated member doesn't participate in", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `pin-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob"), sub("mem")] })).id;
    const start = new Date(Date.now() + 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, `pin private ${run}`), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC", channelId: ch } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: ws, eventId: ev!.id, sub: sub("bob") } as never);
    const [ok] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, `pin team ${run}`), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    for (const a of ["bob", "mem"]) await db().insert(eventAttendees).values({ workspaceId: ws, eventId: ok!.id, sub: sub(a) } as never);
    await postAndPinCalendarSummary(ws, ch, sub("alice"), 7);
    const body = (await listMessages(ws, ch)).map((m) => m.body).join("\n");
    expect(body).not.toContain(`pin private ${run}`);
    expect(body).toContain(`pin team ${run}`);
  });

  it("thread.summarize in a channel reply: only channels every reader is seated in (current channel ok)", async () => {
    const lead = (await createChannel({ workspaceId: ws, kind: "channel", name: `lead-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
    await sendMessage({ workspaceId: ws, channelId: lead, authorSub: sub("alice"), body: `LEADERSHIP-CHANNEL ${run}` });
    const gen = (await createChannel({ workspaceId: ws, kind: "channel", name: `g2-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob"), sub("mem")] })).id;
    await sendMessage({ workspaceId: ws, channelId: gen, authorSub: sub("mem"), body: `GEN ${run}` });
    const t = await tools("bob", gen);
    await expect(t["thread.summarize"]!.execute({ channelId: lead, limit: 20 })).rejects.toThrow(/not every reader/);
    const cur = (await t["thread.summarize"]!.execute({ channelId: gen, limit: 20 })) as { messages: { body: string }[] };
    expect(cur.messages.map((m) => m.body)).toContain(`GEN ${run}`);
    // outside a channel reply (1:1 chat / MCP) bob may still summarize a channel he's in
    const solo = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("bob"), agentRole: "Agent", invokerRole: "Member", audit: false }) as unknown as T;
    expect(JSON.stringify(await solo["thread.summarize"]!.execute({ channelId: lead, limit: 20 }))).toContain(`LEADERSHIP-CHANNEL ${run}`);
  });
});

describe("pass-5: agent seats don't block calendar details; registry is read-only under an audience", () => {
  it("alice+bob+agent channel shows the alice/bob event in full; a non-participant human forces busy-only", async () => {
    await addMember(ws, "agent1", "Agent");
    await addMember(ws, "carol", "Member");
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: `ab-agent-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob"), sub("agent1")] })).id;
    const start = new Date(Date.now() + 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, `ab sync ${run}`), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: ws, eventId: ev!.id, sub: sub("bob") } as never);
    expect(JSON.stringify(await (await tools("alice", ch))["calendar.read"]!.execute({}))).toContain(`ab sync ${run}`);
    // the pinned summary follows the same rule (the pinning agent is seated)
    await postAndPinCalendarSummary(ws, ch, sub("agent1"), 7);
    expect((await listMessages(ws, ch)).map((m) => m.body).join("\n")).toContain(`ab sync ${run}`);
    // an INACTIVE agent seat is not exempt: it counts as external -> Partner scope, no calendar at all (fail closed)
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("agent1"))));
    expect((await tools("alice", ch))["calendar.read"]).toBeUndefined();
    await db().update(members).set({ status: "active" }).where(and(eq(members.workspaceId, ws), eq(members.sub, sub("agent1"))));
    // a seated human who isn't a participant forces busy-only again
    await addChannelMembers(ws, ch, [sub("carol")]);
    const txt = JSON.stringify(await (await tools("alice", ch))["calendar.read"]!.execute({}));
    expect(txt).not.toContain(`ab sync ${run}`);
    expect(txt).toContain("busy");
  });

  it("with an audience set, the registry withholds HIC write tools and web.* even if the caller allows them", () => {
    const allow = new Set(["crm.write", "terminal.exec", "calendar.schedule", "web.fetch", "crm.read"] as never[]);
    const scoped = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audience: [{ sub: sub("alice"), internal: true }], allow: allow as never, audit: false });
    expect(Object.keys(scoped)).toEqual(["crm.read"]);
    const full = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audit: false });
    for (const t of HITL_TOOLS) if (t in (full as object)) expect(Object.keys(citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audience: [{ sub: sub("alice"), internal: true }] }))).not.toContain(t);
    expect(Object.keys(full)).toContain("crm.write"); // unchanged outside channel replies
  });
});
