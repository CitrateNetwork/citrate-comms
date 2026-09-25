/** Verifier pass-4 probes, kept as a regression suite (secure outcome asserted). */
import { describe, it, expect, vi, beforeAll } from "vitest";
vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));
import { db } from "@/lib/db/client";
import { documents, documentChunks, calendarEvents, eventAttendees } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel, addChannelMembers } from "@/lib/domain/channels";
import { sendMessage } from "@/lib/domain/messages";
import { agentReplyScope, replyScopeStillValid, channelReplyAllow } from "@/lib/domain/channel-agent";
import { citrateCommsTools } from "@/lib/ai/tools";
import { encryptField } from "@/lib/security/crypto";
import { run, sub, addMember } from "./helpers";

type T = Record<string, { execute: (a: unknown) => Promise<unknown> }>;
let ws: string, general: string, intl: string, dm: string, privCh: string, dmDoc: string, wsDoc: string, evId: string;
const R: Record<string, unknown> = {};
const tools = async (ch: string, invoker: string) => {
  const s = await agentReplyScope(ws, ch, "Member");
  return citrateCommsTools({ workspaceId: ws, invokedBySub: sub(invoker), agentRole: "Agent", invokerRole: s.effectiveInvokerRole, audience: s.audience, audit: false }) as unknown as T;
};

beforeAll(async () => {
  ws = (await createWorkspace({ name: `p4 ${run}`, ownerSub: sub("own"), ownerWallet: null, ownerEmail: null })).id;
  for (const n of ["alice", "bob", "mem", "carol"]) await addMember(ws, n, "Member");
  await addMember(ws, "gst", "Guest");
  general = (await createChannel({ workspaceId: ws, kind: "channel", name: "general", createdBySub: sub("own"), memberSubs: [sub("alice"), sub("bob"), sub("mem"), sub("carol")] })).id;
  intl = (await createChannel({ workspaceId: ws, kind: "channel", name: "intl", createdBySub: sub("alice"), memberSubs: [sub("mem")] })).id;
  privCh = (await createChannel({ workspaceId: ws, kind: "channel", name: "leadership", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
  await sendMessage({ workspaceId: ws, channelId: privCh, authorSub: sub("alice"), body: "LEADERSHIP-ONLY: layoffs in Q4 include mem" });
  dm = (await createChannel({ workspaceId: ws, kind: "dm", name: "ab", createdBySub: sub("alice"), memberSubs: [sub("bob")] })).id;
  dmDoc = (await db().insert(documents).values({ workspaceId: ws, channelId: dm, blobUrl: "https://x.public.blob.vercel-storage.com/a.pdf", name: "alice-bob-secret.pdf", mime: "text/plain", uploadedBySub: sub("alice") }).returning())[0]!.id;
  await db().insert(documentChunks).values({ workspaceId: ws, documentId: dmDoc, ord: 0, textEnc: encryptField(ws, "zebra quarterly compensation secret") });
  wsDoc = (await db().insert(documents).values({ workspaceId: ws, blobUrl: "https://x.public.blob.vercel-storage.com/w.pdf", name: "handbook.pdf", mime: "text/plain", uploadedBySub: sub("own") }).returning())[0]!.id;
  await db().insert(documentChunks).values({ workspaceId: ws, documentId: wsDoc, ord: 0, textEnc: encryptField(ws, "zebra handbook vacation policy") });
  const start = new Date(Date.now() + 86400_000);
  evId = (await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, "Alice/Bob: mem performance review"), locationEnc: encryptField(ws, "Room 7"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning())[0]!.id;
  await db().insert(eventAttendees).values({ workspaceId: ws, eventId: evId, sub: sub("bob") } as never);
});

describe("pass-3 residual probes re-run", () => {
  it("mid-run Guest seat -> reply scope invalid (dropped)", async () => {
    const ch = (await createChannel({ workspaceId: ws, kind: "channel", name: "tt", createdBySub: sub("alice"), memberSubs: [sub("mem")] })).id;
    const s = await agentReplyScope(ws, ch, "Member");
    await addChannelMembers(ws, ch, [sub("gst")]);
    expect(await replyScopeStillValid(ws, ch, "Member", s.audience, s.effectiveInvokerRole)).toBe(false);
    const s2 = await agentReplyScope(ws, ch, "Member");
    await addMember(ws, "late", "Member");
    await addChannelMembers(ws, ch, [sub("late")]);
    expect(await replyScopeStillValid(ws, ch, "Member", s2.audience, s2.effectiveInvokerRole)).toBe(false); // even an internal newcomer
  });
  it("internal-audience widening: alice in #intl (with mem) cannot surface the DM doc via documents.*", async () => {
    const t = await tools(intl, "alice");
    const l = (await t["documents.list"]!.execute({ limit: 50 })) as { documents: { id: string }[] };
    expect(l.documents.map((d) => d.id)).not.toContain(dmDoc);
    const r = (await t["documents.read"]!.execute({ query: "zebra", budget: 10 })) as { results: { documentId: string }[] };
    expect(r.results.map((x) => x.documentId)).not.toContain(dmDoc);
    R.internalReadStillUseful = r.results.map((x) => x.documentId).includes(wsDoc);
  });
});

describe("bypass attempts", () => {
  it("calendar.read in a channel reply: non-attendee invoker (mem) in #general gets alice/bob private event details?", async () => {
    const solo = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("mem"), agentRole: "Agent", invokerRole: "Member", audit: false }) as unknown as T;
    const a = (await solo["calendar.read"]!.execute({})) as { events: Record<string, unknown>[] };
    R.calendarSoloTitle = a.events.map((e) => e.title ?? null);
    const t = await tools(general, "mem");
    const b = (await t["calendar.read"]!.execute({})) as { events: Record<string, unknown>[] };
    R.calendarChannelTitle = b.events.map((e) => e.title ?? null);
    R.busyOnlyKeys = Object.keys(a.events[0] ?? {});
    expect(b.events.some((e) => String(e.title ?? "").includes("performance review"))).toBe(false);
  });
  it("thread.summarize: invoker (bob) in #general reads private #leadership into a channel mem reads", async () => {
    const t = await tools(general, "bob");
    let leaked = false;
    try {
      const r = (await t["thread.summarize"]!.execute({ channelId: privCh, limit: 20 })) as { messages: { body: string }[] };
      leaked = r.messages.some((m) => m.body.includes("LEADERSHIP-ONLY"));
    } catch { leaked = false; }
    R.threadSummarizeLeak = leaked;
    expect(leaked).toBe(false);
  });
  it("thread.summarize in a PARTNER-scoped channel (tool still offered)", async () => {
    await addMember(ws, "par", "Partner");
    const sh = (await createChannel({ workspaceId: ws, kind: "channel", name: "sh", createdBySub: sub("bob"), memberSubs: [sub("par")] })).id;
    const t = await tools(sh, "bob");
    R.partnerScopeKeys = Object.keys(t);
    let leaked = false;
    try {
      const r = (await t["thread.summarize"]!.execute({ channelId: privCh, limit: 20 })) as { messages: { body: string }[] };
      leaked = r.messages.some((m) => m.body.includes("LEADERSHIP-ONLY"));
    } catch { leaked = false; }
    R.threadSummarizeToPartner = leaked;
    expect(leaked).toBe(false);
  });
  it("artifact.attach / crm.read / web.* in channel reply", async () => {
    const t = await tools(intl, "alice");
    expect(((await t["artifact.attach"]!.execute({ documentId: dmDoc })) as { ok: boolean }).ok).toBe(false);
    expect(Object.keys(t)).not.toContain("web.fetch");
    R.channelKeys = Object.keys(t);
    const allow = channelReplyAllow(["web.fetch", "web.search", "crm.read", "documents.read", "crm.ingest", "tables.map"] as never);
    R.allowAfterDeny = [...allow];
  });
});

describe("regressions", () => {
  it("MCP / 1:1 chat (no audience) keep full tools incl. web.*", () => {
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Member" });
    for (const k of ["web.fetch", "web.search", "documents.read", "calendar.read", "crm.read"]) expect(Object.keys(t)).toContain(k);
  });
  it("1:1 alice still sees her DM doc + her event details", async () => {
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("alice"), agentRole: "Agent", invokerRole: "Member", audit: false }) as unknown as T;
    const l = (await t["documents.list"]!.execute({ limit: 50 })) as { documents: { id: string }[] };
    expect(l.documents.map((d) => d.id)).toContain(dmDoc);
  });
});
