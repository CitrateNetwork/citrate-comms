/**
 * PBA-R2 authorization regression suite: tenant, role, channel and document access
 * behaviour for the web tier's route handlers.
 *
 * Real route handlers, real Postgres (every migration applied), real mock-auth path.
 * Only the Upstash rate limiter is replaced (it would otherwise fail closed without Redis).
 */
import { describe, it, expect, vi, beforeAll } from "vitest";

const limitCalls: string[] = [];
const limiter = { denyPrefix: null as string | null };
vi.mock("@/lib/security/ratelimit", () => ({
  limit: async (key: string) => {
    limitCalls.push(key);
    return { success: !(limiter.denyPrefix && key.startsWith(limiter.denyPrefix)), remaining: 99 };
  },
  rateLimitConfigured: () => true,
}));
// Stub only the network-signing primitive; the download proxy still runs the real
// per-document authorization before it mints a URL, and the URL encodes the download
// disposition so tests can assert it (ATT-HARDEN).
vi.mock("@/lib/security/blob-signing", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  signedReadUrl: async (_url: string, opts?: { download?: boolean }) => ({ url: `https://signed.example/read${opts?.download ? "?download=1" : ""}`, expiresAt: Date.now() + 120_000 }),
}));

import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, documentChunks, agentPrompts, agentSkills, agentResources, agentConfigGrants, calendarEvents, eventAttendees, ledgerEntries, messageAttachments, channelMembers, invites } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel } from "@/lib/domain/channels";
import { listPersonas, seedDefaultPersonas, resolvePersona, setPromptLayer, setSkillEnabled } from "@/lib/domain/personas";
import { addResource, grantConfig, canConfigurePersona } from "@/lib/domain/agent-config";
import { createInvite, acceptInvite } from "@/lib/domain/invites";
import { encryptField, hashToken } from "@/lib/security/crypto";
import { personaInWorkspace } from "@/lib/domain/persona-scope";
import { witness } from "@/lib/witness/ledger";

import * as promptsRoute from "@/app/api/workspaces/[id]/personas/[personaId]/prompts/route";
import * as skillsRoute from "@/app/api/workspaces/[id]/personas/[personaId]/skills/route";
import * as personaRoute from "@/app/api/workspaces/[id]/personas/[personaId]/route";
import * as resourcesRoute from "@/app/api/workspaces/[id]/personas/[personaId]/resources/route";
import * as grantsRoute from "@/app/api/workspaces/[id]/persona-config-grants/route";
import * as msgRoute from "@/app/api/channels/[id]/messages/route";
import * as dlRoute from "@/app/api/workspaces/[id]/documents/[docId]/download/route";
import * as mcpRoute from "@/app/api/workspaces/[id]/mcp/route";
import * as accountsRoute from "@/app/api/workspaces/[id]/accounts/route";
import * as ledgerRoute from "@/app/api/channels/[id]/ledger/route";
import * as calEventRoute from "@/app/api/workspaces/[id]/calendar/[eventId]/route";
import * as agentChatRoute from "@/app/api/workspaces/[id]/agents/[agentId]/chat/route";
import * as finalizeRoute from "@/app/api/workspaces/[id]/documents/finalize/route";
import * as tagsRoute from "@/app/api/workspaces/[id]/crm/[entity]/[recordId]/tags/route";
import * as bulkTagRoute from "@/app/api/workspaces/[id]/crm/[entity]/bulk-tag/route";
import * as channelsRoute from "@/app/api/channels/route";
import * as invitesRoute from "@/app/api/workspaces/[id]/invites/route";
import * as inviteBatchRoute from "@/app/api/workspaces/[id]/invites/batch/route";
import { crmRecordTags } from "@/lib/db/schema";
import { run, sub, req, P, addMember, mcpCall } from "./helpers";

type McpResult = { result?: { isError?: boolean; structuredContent?: Record<string, unknown>; tools?: { name: string }[] }; error?: { code: number; message: string } };

let wsA: string, wsB: string;
let personaA: string;

beforeAll(async () => {
  wsA = (await createWorkspace({ name: `workspace-a ${run}`, ownerSub: sub("vowner"), ownerWallet: null, ownerEmail: null })).id;
  wsB = (await createWorkspace({ name: `workspace-b ${run}`, ownerSub: sub("otherowner"), ownerWallet: null, ownerEmail: null })).id;
  await seedDefaultPersonas(wsA, sub("vowner"));
  await seedDefaultPersonas(wsB, sub("otherowner"));
  personaA = (await listPersonas(wsA))[0]!.id;
});

describe("PBA-L3c-001 persona config is bound to its workspace", () => {
  it("an Owner of ANOTHER workspace cannot overwrite the workspace A persona's prompt layer", async () => {
    let r = await promptsRoute.POST(req(`/api/workspaces/${wsA}/personas/${personaA}/prompts`, "vowner", { method: "POST", body: JSON.stringify({ layer: 1, content: "OWNER MISSION" }) }), P({ id: wsA, personaId: personaA }));
    expect(r.status).toBe(200);
    expect((await resolvePersona(wsA, personaA))!.overrides.mission).toBe("OWNER MISSION");

    r = await promptsRoute.POST(req(`/api/workspaces/${wsB}/personas/${personaA}/prompts`, "otherowner", { method: "POST", body: JSON.stringify({ layer: 1, content: "OTHER-WORKSPACE" }) }), P({ id: wsB, personaId: personaA }));
    expect(r.status).toBe(403);

    const [row] = await db().select().from(agentPrompts).where(and(eq(agentPrompts.personaId, personaA), eq(agentPrompts.layer, 1)));
    expect(row!.workspaceId).toBe(wsA);
    expect(row!.updatedBySub).toBe(sub("vowner"));
    expect((await resolvePersona(wsA, personaA))!.overrides.mission).toBe("OWNER MISSION");
  });

  it("an Owner of another workspace cannot toggle the workspace A persona's skills", async () => {
    await setSkillEnabled(wsA, personaA, "pba-skill", true);
    const [s] = await db().select().from(agentSkills).where(and(eq(agentSkills.personaId, personaA), eq(agentSkills.skillKey, "pba-skill")));
    const r = await skillsRoute.POST(req(`/api/workspaces/${wsB}/personas/${personaA}/skills`, "otherowner", { method: "POST", body: JSON.stringify({ skillKey: s!.skillKey, enabled: false }) }), P({ id: wsB, personaId: personaA }));
    expect(r.status).toBe(403);
    const [after] = await db().select().from(agentSkills).where(eq(agentSkills.id, s!.id));
    expect(after!.enabled).toBe(true);
  });

  it("cross-tenant persona read/patch/resources/grant are refused", async () => {
    const g = await personaRoute.GET(req(`/api/workspaces/${wsB}/personas/${personaA}`, "otherowner"), P({ id: wsB, personaId: personaA }));
    expect(g.status).toBe(403);
    const pa = await personaRoute.PATCH(req(`/api/workspaces/${wsB}/personas/${personaA}`, "otherowner", { method: "PATCH", body: JSON.stringify({ enabled: false }) }), P({ id: wsB, personaId: personaA }));
    expect(pa.status).toBe(403);
    const rs = await resourcesRoute.POST(req(`/api/workspaces/${wsB}/personas/${personaA}/resources`, "otherowner", { method: "POST", body: JSON.stringify({ kind: "text", title: "x", content: "note" }) }), P({ id: wsB, personaId: personaA }));
    expect(rs.status).toBe(403);
    const gr = await grantsRoute.POST(req(`/api/workspaces/${wsB}/persona-config-grants`, "otherowner", { method: "POST", body: JSON.stringify({ granteeSub: sub("otherowner"), personaId: personaA }) }), P({ id: wsB }));
    expect(gr.status).toBe(403);
    expect(await db().select().from(agentResources).where(eq(agentResources.personaId, personaA))).toHaveLength(0);
    expect(await db().select().from(agentConfigGrants).where(eq(agentConfigGrants.personaId, personaA))).toHaveLength(0);
  });

  it("domain layer refuses a foreign persona even if a route forgot to check", async () => {
    await expect(setPromptLayer(wsB, personaA, 2, "x", sub("otherowner"))).rejects.toThrow(/persona not in this workspace/);
    await expect(setSkillEnabled(wsB, personaA, "pba-skill", false)).rejects.toThrow(/persona not in this workspace/);
    await expect(addResource(wsB, personaA, { kind: "text", title: "t", content: "c" }, sub("otherowner"))).rejects.toThrow(/persona not in this workspace/);
    await expect(grantConfig(wsB, sub("otherowner"), personaA, sub("otherowner"))).rejects.toThrow(/persona not in this workspace/);
    expect(await canConfigurePersona(wsB, sub("otherowner"), "Owner", personaA)).toBe(false);
    expect(await canConfigurePersona(wsA, sub("vowner"), "Owner", personaA)).toBe(true);
  });

  it("a pre-existing cross-tenant row is never rewritten by an upsert (setWhere)", async () => {
    // Simulate a pre-existing row: workspace-B row on a workspace-A persona.
    const preexisting = (await listPersonas(wsA))[1]!.id;
    await db().insert(agentPrompts).values({ workspaceId: wsB, personaId: preexisting, layer: 3, contentEnc: encryptField(wsB, "PREEXISTING"), updatedBySub: sub("otherowner") }).catch(() => undefined);
    const [before] = await db().select().from(agentPrompts).where(and(eq(agentPrompts.personaId, preexisting), eq(agentPrompts.layer, 3)));
    if (!before) return; // migration 0016's composite FK refused the pre-existing row outright — stronger still
    await setPromptLayer(wsA, preexisting, 3, "owner-content", sub("vowner"));
    const [after] = await db().select().from(agentPrompts).where(and(eq(agentPrompts.personaId, preexisting), eq(agentPrompts.layer, 3)));
    expect(after!.workspaceId).toBe(wsB);
    expect(after!.updatedBySub).toBe(sub("otherowner"));
  });
});

describe("PBA-L3c-003 private-channel / DM attachments stay private", () => {
  let dmDocId: string;
  let wsDocId: string;
  beforeAll(async () => {
    await addMember(wsA, "alice", "Member");
    await addMember(wsA, "bob", "Member");
    await addMember(wsA, "eve", "Member");
    await addMember(wsA, "guest", "Guest");
    const dm = await createChannel({ workspaceId: wsA, kind: "dm", name: "alice-bob", createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const [d] = await db().insert(documents).values({ workspaceId: wsA, channelId: dm.id, blobUrl: `https://privstore.private.blob.vercel-storage.com/comms/${wsA}/offer-letter-bob.pdf`, name: "offer-letter-bob.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    dmDocId = d!.id;
    await db().insert(documentChunks).values({ workspaceId: wsA, documentId: dmDocId, ord: 0, textEnc: encryptField(wsA, "compensation offer bob notes") });
    const [w] = await db().insert(documents).values({ workspaceId: wsA, blobUrl: "https://x.public.blob.vercel-storage.com/handbook.pdf", name: "handbook.pdf", mime: "application/pdf", uploadedBySub: sub("vowner") }).returning();
    wsDocId = w!.id;
    await db().insert(documentChunks).values({ workspaceId: wsA, documentId: wsDocId, ord: 0, textEnc: encryptField(wsA, "compensation policy handbook") });
  });

  const mcp = async (who: string, name: string, args: Record<string, unknown>) =>
    (await (await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, who, { method: "POST", body: mcpCall(name, args) }), P({ id: wsA }))).json()) as McpResult;

  it("Guest cannot use documents.list at all (external role, deny by default)", async () => {
    const j = await mcp("guest", "documents.list", { limit: 50 });
    expect(j.error?.message ?? "").toMatch(/Unknown tool/);
    expect(JSON.stringify(j)).not.toContain(dmDocId);
  });

  it("Eve (not in the alice-bob DM) is refused the DM attachment download; bob gets it", async () => {
    const r = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${dmDocId}/download`, "eve"), P({ id: wsA, docId: dmDocId }));
    expect(r.status).toBe(403);
    expect(r.headers.get("location")).toBeNull();
    const ok = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${dmDocId}/download`, "bob"), P({ id: wsA, docId: dmDocId }));
    expect(ok.status).toBe(302);
  });

  it("documents.list / documents.read (RAG) / artifact.attach are viewer-scoped for a Member", async () => {
    const evList = await mcp("eve", "documents.list", { limit: 50 });
    const evIds = (evList.result!.structuredContent!.documents as { id: string }[]).map((d) => d.id);
    expect(evIds).not.toContain(dmDocId);
    expect(evIds).toContain(wsDocId);
    const alList = await mcp("alice", "documents.list", { limit: 50 });
    expect((alList.result!.structuredContent!.documents as { id: string }[]).map((d) => d.id)).toContain(dmDocId);

    const evRag = await mcp("eve", "documents.read", { query: "compensation", budget: 10 });
    const evRagIds = (evRag.result!.structuredContent!.results as { documentId: string }[]).map((x) => x.documentId);
    expect(evRagIds).not.toContain(dmDocId);
    expect(evRagIds).toContain(wsDocId);
    const alRag = await mcp("alice", "documents.read", { query: "compensation", budget: 10 });
    expect((alRag.result!.structuredContent!.results as { documentId: string }[]).map((x) => x.documentId)).toContain(dmDocId);

    const att = await mcp("eve", "artifact.attach", { documentId: dmDocId });
    expect(att.result!.structuredContent).toMatchObject({ ok: false, error: "document_not_found" });
  });

  it("a Guest can download a file shared into a channel they are seated in, nothing else", async () => {
    const ch = await createChannel({ workspaceId: wsA, kind: "channel", name: `shared-${run}`, createdBySub: sub("alice"), memberSubs: [sub("guest")] });
    const [d] = await db().insert(documents).values({ workspaceId: wsA, channelId: ch.id, blobUrl: `https://privstore.private.blob.vercel-storage.com/comms/${wsA}/shared.pdf`, name: "shared.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    expect((await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${d!.id}/download`, "guest"), P({ id: wsA, docId: d!.id }))).status).toBe(302);
    expect((await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${wsDocId}/download`, "guest"), P({ id: wsA, docId: wsDocId }))).status).toBe(403);
    expect((await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${dmDocId}/download`, "guest"), P({ id: wsA, docId: dmDocId }))).status).toBe(403);
  });
});

describe("PBA-L3c-002 Partner/Guest are scoped to their channels", () => {
  beforeAll(async () => {
    await addMember(wsA, "partner", "Partner");
    const { createAccount } = await import("@/lib/domain/crm");
    await createAccount(wsA, "Acme Secret Prospect", "acme.example", sub("vowner"));
  });

  it("external Partner gets 403 on the account list; a Member still reads it", async () => {
    const r = await accountsRoute.GET(req(`/api/workspaces/${wsA}/accounts`, "partner"), P({ id: wsA }));
    expect(r.status).toBe(403);
    expect(JSON.stringify(await r.json())).not.toContain("Acme Secret Prospect");
    const m = await accountsRoute.GET(req(`/api/workspaces/${wsA}/accounts`, "eve"), P({ id: wsA }));
    expect(m.status).toBe(200);
    expect(JSON.stringify(await m.json())).toContain("Acme Secret Prospect");
  });

  it("Guest/Partner MCP surface lists only channel-scoped tools; crm.read is unknown to them", async () => {
    for (const who of ["guest", "partner"]) {
      const r = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, who, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }), P({ id: wsA }));
      const names = ((await r.json()) as McpResult).result!.tools!.map((t) => t.name);
      expect(names).toEqual(["thread.summarize"]);
      const c = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, who, { method: "POST", body: mcpCall("crm.read", { entity: "account" }) }), P({ id: wsA }));
      const txt = JSON.stringify(await c.json());
      expect(txt).not.toContain("Acme Secret Prospect");
      expect(txt).toMatch(/Unknown tool/);
    }
  });

  it("calendar: a non-attendee Guest cannot read an event by id; Partner MCP calendar.read is unavailable", async () => {
    const start = new Date(Date.now() + 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: wsA, kind: "meeting", titleEnc: encryptField(wsA, "Restricted planning (HR only)"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: wsA, eventId: ev!.id, sub: sub("alice") } as never);
    const r1 = await calEventRoute.GET(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "guest"), P({ id: wsA, eventId: ev!.id }));
    expect([403, 404]).toContain(r1.status);
    expect(JSON.stringify(await r1.json())).not.toContain("Restricted planning");
    const r2 = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "partner", { method: "POST", body: mcpCall("calendar.read", {}) }), P({ id: wsA }));
    expect(JSON.stringify(await r2.json())).not.toContain("Restricted planning");
  });

  it("a Partner cannot drive the agent chat (which would read CRM as role=Agent)", async () => {
    const pid = (await listPersonas(wsA))[0]!.id;
    const r = await agentChatRoute.POST(req(`/api/workspaces/${wsA}/agents/${pid}/chat`, "partner", { method: "POST", body: JSON.stringify({ messages: [{ role: "user", parts: [{ type: "text", text: "list accounts" }] }] }) }), P({ id: wsA, agentId: pid }));
    expect(r.status).toBe(403);
  });

  it("a Partner invite scoped to a channel seats the partner in exactly that channel", async () => {
    const ch = await createChannel({ workspaceId: wsA, kind: "channel", name: `deal-room-${run}`, createdBySub: sub("vowner") });
    const inv = await createInvite({ workspaceId: wsA, email: `p-${run}@example.com`, role: "Partner", invitedBySub: sub("vowner"), scopeChannelId: ch.id });
    const res = await acceptInvite({ token: inv.token, sub: sub("partner2") });
    expect(res.ok).toBe(true);
    const seats = await db().select().from(channelMembers).where(eq(channelMembers.sub, sub("partner2")));
    expect(seats.map((s) => s.channelId)).toEqual([ch.id]);
    const { members } = await import("@/lib/db/schema");
    const [m] = await db().select().from(members).where(and(eq(members.workspaceId, wsA), eq(members.sub, sub("partner2"))));
    expect([m?.role, m?.status]).toEqual(["Partner", "active"]);
    const foreign = await createChannel({ workspaceId: wsB, kind: "channel", name: "x", createdBySub: sub("otherowner") });
    await expect(createInvite({ workspaceId: wsA, email: `q-${run}@example.com`, role: "Partner", invitedBySub: sub("vowner"), scopeChannelId: foreign.id })).rejects.toThrow(/scope channel/);
  });
});

describe("PBA-L3c-005 message attachments must be the workspace's (and visible) documents", () => {
  it("linking a document id from ANOTHER workspace is rejected with 400 and nothing is linked", async () => {
    const [doc] = await db().insert(documents).values({ workspaceId: wsA, blobUrl: "https://x.public.blob.vercel-storage.com/board-deck-q3-abc.pdf", name: "board-deck-q3.pdf", mime: "application/pdf", uploadedBySub: sub("vowner") }).returning();
    const ch = await createChannel({ workspaceId: wsB, kind: "channel", name: "x", createdBySub: sub("otherowner") });
    const r = await msgRoute.POST(req(`/api/channels/${ch.id}/messages`, "otherowner", { method: "POST", body: JSON.stringify({ body: "", attachmentIds: [doc!.id] }) }), P({ id: ch.id }));
    expect(r.status).toBe(400);
    expect(JSON.stringify(await r.json())).not.toContain("board-deck-q3");
    expect(await db().select().from(messageAttachments).where(eq(messageAttachments.documentId, doc!.id))).toHaveLength(0);
  });

  it("a member cannot re-share a DM attachment they cannot see into a channel", async () => {
    const dm = await createChannel({ workspaceId: wsA, kind: "dm", name: "a-b-2", createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const [d] = await db().insert(documents).values({ workspaceId: wsA, channelId: dm.id, blobUrl: "https://x.public.blob.vercel-storage.com/p.pdf", name: "p.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    const pub = await createChannel({ workspaceId: wsA, kind: "channel", name: `pub-${run}`, createdBySub: sub("vowner"), memberSubs: [sub("eve")] });
    const r = await msgRoute.POST(req(`/api/channels/${pub.id}/messages`, "eve", { method: "POST", body: JSON.stringify({ body: "", attachmentIds: [d!.id] }) }), P({ id: pub.id }));
    expect(r.status).toBe(400);
  });
});

describe("PBA-L3c-009 clients never receive raw Blob URLs; finalize is pinned to this store", () => {
  it("a message attachment is served as the access-controlled inline proxy URL", async () => {
    const ch = await createChannel({ workspaceId: wsA, kind: "channel", name: `att-${run}`, createdBySub: sub("alice") });
    const [d] = await db().insert(documents).values({ workspaceId: wsA, channelId: ch.id, blobUrl: `https://privstore.private.blob.vercel-storage.com/comms/${wsA}/diagram.png`, name: "diagram.png", mime: "image/png", uploadedBySub: sub("alice") }).returning();
    const r = await msgRoute.POST(req(`/api/channels/${ch.id}/messages`, "alice", { method: "POST", body: JSON.stringify({ body: "see", attachmentIds: [d!.id] }) }), P({ id: ch.id }));
    expect(r.status).toBe(201);
    const j = (await r.json()) as { message: { attachments: { url: string }[] } };
    expect(j.message.attachments[0]!.url).toBe(`/api/workspaces/${wsA}/documents/${d!.id}/download?inline=1`);
    expect(JSON.stringify(j)).not.toContain("blob.vercel-storage.com");
    // inline view: same authorization as a download
    expect((await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${d!.id}/download?inline=1`, "eve"), P({ id: wsA, docId: d!.id }))).status).toBe(403);
    const ok = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${d!.id}/download?inline=1`, "alice"), P({ id: wsA, docId: d!.id }));
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).not.toContain("download=1");
  });

  it("finalize binds the object to this workspace's private store (rejects foreign store, public, cross-workspace)", async () => {
    const prev = process.env.BLOB_READ_WRITE_TOKEN;
    process.env.BLOB_READ_WRITE_TOKEN = "vercel_blob_rw_Store1_testfixture"; // private host: store1.private.…
    const fin = (blobUrl: string, workspaceId = wsA) =>
      finalizeRoute.POST(req(`/api/workspaces/${workspaceId}/documents/finalize`, workspaceId === wsA ? "alice" : "otherowner", { method: "POST", body: JSON.stringify({ blobUrl, name: "x.png", mime: "image/png" }) }), P({ id: workspaceId }));
    try {
      // another store entirely → bad_host
      const foreign = await fin("https://otherstore9.private.blob.vercel-storage.com/comms/" + wsA + "/x.png");
      expect(foreign.status).toBe(400);
      expect(await foreign.json()).toMatchObject({ error: "bad_host" });

      // this deployment but the PUBLIC (legacy) host → rejected: new uploads must be private
      const pub = await fin(`https://store1.public.blob.vercel-storage.com/comms/${wsA}/x.png`);
      expect(pub.status).toBe(400);
      expect(await pub.json()).toMatchObject({ error: "bad_host" });

      // private, but under ANOTHER workspace's prefix → bad_scope (can't claim wsB's namespace)
      const foreignPrefix = await fin(`https://store1.private.blob.vercel-storage.com/comms/${wsB}/x.png`);
      expect(foreignPrefix.status).toBe(400);
      expect(await foreignPrefix.json()).toMatchObject({ error: "bad_scope" });

      // an object already bound to another workspace's document → bad_scope (covers legacy,
      // unprefixed pathnames a caller might replay). Seed a wsB row, then try to re-register it.
      const shared = `https://store1.private.blob.vercel-storage.com/comms/${wsA}/collision.png`;
      await db().insert(documents).values({ workspaceId: wsB, blobUrl: shared, name: "v.png", mime: "image/png", uploadedBySub: sub("otherowner") });
      const stolen = await fin(shared);
      expect(stolen.status).toBe(400);
      expect(await stolen.json()).toMatchObject({ error: "bad_scope" });

      // the happy path: this deployment's private store, under this workspace's prefix
      const good = await fin(`https://store1.private.blob.vercel-storage.com/comms/${wsA}/x.png`);
      expect(good.status).toBe(201);
    } finally {
      if (prev === undefined) delete process.env.BLOB_READ_WRITE_TOKEN;
      else process.env.BLOB_READ_WRITE_TOKEN = prev;
    }
  });
});

describe("PBA-L3c-007 calendar events: creator/attendees read, creator/admin edit", () => {
  it("a Member who is not an attendee cannot read, edit or cancel someone else's event", async () => {
    const start = new Date(Date.now() + 2 * 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: wsA, kind: "meeting", titleEnc: encryptField(wsA, "1:1 alice/bob"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: wsA, eventId: ev!.id, sub: sub("bob") } as never);
    const g = await calEventRoute.GET(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "eve"), P({ id: wsA, eventId: ev!.id }));
    expect(g.status).toBe(404);
    // a non-attendee can't even see it, so a write is "not found" (existence is not revealed)
    const p = await calEventRoute.PATCH(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "eve", { method: "PATCH", body: JSON.stringify({ title: "renamed" }) }), P({ id: wsA, eventId: ev!.id }));
    expect(p.status).toBe(404);
    const d = await calEventRoute.DELETE(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "eve", { method: "DELETE" }), P({ id: wsA, eventId: ev!.id }));
    expect(d.status).toBe(404);
    const [still] = await db().select().from(calendarEvents).where(eq(calendarEvents.id, ev!.id));
    expect(still!.status).not.toBe("cancelled");
    // attendee reads; attendee (non-creator Member) may not edit; creator edits; Owner cancels
    expect((await calEventRoute.GET(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "bob"), P({ id: wsA, eventId: ev!.id }))).status).toBe(200);
    expect((await calEventRoute.PATCH(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "bob", { method: "PATCH", body: JSON.stringify({ title: "x" }) }), P({ id: wsA, eventId: ev!.id }))).status).toBe(403);
    expect((await calEventRoute.PATCH(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "alice", { method: "PATCH", body: JSON.stringify({ title: "1:1 moved" }) }), P({ id: wsA, eventId: ev!.id }))).status).toBe(200);
    expect((await calEventRoute.GET(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "vowner"), P({ id: wsA, eventId: ev!.id }))).status).toBe(200);
    expect((await calEventRoute.DELETE(req(`/api/workspaces/${wsA}/calendar/${ev!.id}`, "vowner", { method: "DELETE" }), P({ id: wsA, eventId: ev!.id }))).status).toBe(200);
  });

  it("calendar.read (MCP) shows a non-attended event as busy only (no title) to a Member", async () => {
    const start = new Date(Date.now() + 3 * 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: wsA, kind: "meeting", titleEnc: encryptField(wsA, "Board: planning"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    const r = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "eve", { method: "POST", body: mcpCall("calendar.read", {}) }), P({ id: wsA }));
    const txt = JSON.stringify(await r.json());
    expect(txt).not.toContain("Board: planning");
    expect(txt).toContain("busy");
    const own = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "alice", { method: "POST", body: mcpCall("calendar.read", {}) }), P({ id: wsA }));
    expect(JSON.stringify(await own.json())).toContain("Board: planning");
    expect(ev).toBeTruthy();
  });
});

describe("PBA-L3c-020 ledger PATCH is scoped to the route's channel", () => {
  it("a member of channel A cannot resolve a commitment in private channel B", async () => {
    const a = await createChannel({ workspaceId: wsA, kind: "channel", name: "a", createdBySub: sub("vowner"), memberSubs: [sub("eve")] });
    const b = await createChannel({ workspaceId: wsA, kind: "channel", name: "b", createdBySub: sub("vowner"), memberSubs: [sub("alice")] });
    const entry = await witness({ workspaceId: wsA, channelId: b.id, kind: "commitment", text: "ship", bySub: sub("alice") });
    const r = await ledgerRoute.PATCH(req(`/api/channels/${a.id}/ledger`, "eve", { method: "PATCH", body: JSON.stringify({ entryId: entry.id }) }), P({ id: a.id }));
    expect(r.status).toBe(404);
    const [row] = await db().select().from(ledgerEntries).where(eq(ledgerEntries.id, entry.id));
    expect(row!.status).not.toBe("done");
    const ok = await ledgerRoute.PATCH(req(`/api/channels/${b.id}/ledger`, "alice", { method: "PATCH", body: JSON.stringify({ entryId: entry.id }) }), P({ id: b.id }));
    expect(ok.status).toBe(200);
  });
});

describe("PBA-L3c-006 MCP batches are bounded and every call is charged", () => {
  it("a 300-call batch is rejected before any tool runs", async () => {
    const batch = Array.from({ length: 300 }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "documents.list", arguments: { limit: 1 } } }));
    const r = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "eve", { method: "POST", body: JSON.stringify(batch) }), P({ id: wsA }));
    expect(r.status).toBe(400);
  });

  it("each tools/call in an allowed batch consumes its own rate-limit token", async () => {
    limitCalls.length = 0;
    const batch = Array.from({ length: 5 }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "documents.list", arguments: { limit: 1 } } }));
    const r = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "eve", { method: "POST", body: JSON.stringify(batch) }), P({ id: wsA }));
    expect(r.status).toBe(200);
    expect(((await r.json()) as unknown[]).length).toBe(5);
    expect(limitCalls.filter((k) => k.startsWith("mcp")).length).toBeGreaterThanOrEqual(1 + 5);
  });
});

describe("PBA-L3c-023 invite single-use consume is atomic", () => {
  it("two concurrent accepts of one token admit exactly one identity", async () => {
    const inv = await createInvite({ workspaceId: wsA, email: `race-${run}@example.com`, role: "Member", invitedBySub: sub("vowner") });
    const [a, b] = await Promise.all([acceptInvite({ token: inv.token, sub: sub("racer1") }), acceptInvite({ token: inv.token, sub: sub("racer2") })]);
    expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
    const [row] = await db().select().from(invites).where(eq(invites.email, `race-${run}@example.com`));
    expect(row!.acceptedAt).not.toBeNull();
  });
});

describe("PBA-L3c-027 foreign ids are validated before they are persisted", () => {
  it("tagging with another workspace's tag, or bulk-tagging foreign records, persists nothing", async () => {
    const { createAccount } = await import("@/lib/domain/crm");
    const { createTag } = await import("@/lib/domain/crm-tags");
    const mine = await createAccount(wsA, `Tagged ${run}`, null, sub("vowner"));
    const foreignAcct = await createAccount(wsB, `Foreign ${run}`, null, sub("otherowner"));
    const foreignTag = await createTag(wsB, `ftag-${run}`);
    const r = await tagsRoute.POST(req(`/api/workspaces/${wsA}/crm/account/${mine.id}/tags`, "vowner", { method: "POST", body: JSON.stringify({ tagId: foreignTag.id }) }), P({ id: wsA, entity: "account", recordId: mine.id }));
    expect(r.status).toBe(403);
    const ownTag = await createTag(wsA, `vtag-${run}`);
    const b = await bulkTagRoute.POST(req(`/api/workspaces/${wsA}/crm/account/bulk-tag`, "vowner", { method: "POST", body: JSON.stringify({ tagId: ownTag.id, recordIds: [mine.id, foreignAcct.id, crypto.randomUUID()] }) }), P({ id: wsA, entity: "account" }));
    expect(b.status).toBe(200);
    expect(((await b.json()) as { tagged: number }).tagged).toBe(1);
    const links = await db().select().from(crmRecordTags).where(eq(crmRecordTags.workspaceId, wsA));
    expect(links.map((l) => l.recordId)).not.toContain(foreignAcct.id);
    expect(links.map((l) => l.tagId)).not.toContain(foreignTag.id);
  });

  it("a channel only seats active members of its own workspace", async () => {
    const r = await channelsRoute.POST(req(`/api/channels`, "vowner", { method: "POST", body: JSON.stringify({ workspaceId: wsA, kind: "channel", name: `seat-${run}`, memberSubs: [sub("alice"), sub("otherowner"), "dev:nobody"] }) }));
    expect(r.status).toBe(201);
    const { channel } = (await r.json()) as { channel: { id: string } };
    const seats = (await db().select().from(channelMembers).where(eq(channelMembers.channelId, channel.id))).map((x) => x.sub).sort();
    expect(seats).toEqual([sub("alice"), sub("vowner")].sort());
  });

  it("finalize refuses a foreign channel scope, a channel the uploader isn't in, and a disallowed type", async () => {
    const prev = process.env.BLOB_READ_WRITE_TOKEN;
    process.env.BLOB_READ_WRITE_TOKEN = "vercel_blob_rw_Store1_testfixture";
    try {
      const foreign = await createChannel({ workspaceId: wsB, kind: "channel", name: "f", createdBySub: sub("otherowner") });
      const notMine = await createChannel({ workspaceId: wsA, kind: "channel", name: `nm-${run}`, createdBySub: sub("bob") });
      const call = (body: Record<string, unknown>) => finalizeRoute.POST(req(`/api/workspaces/${wsA}/documents/finalize`, "alice", { method: "POST", body: JSON.stringify({ blobUrl: `https://store1.private.blob.vercel-storage.com/comms/${wsA}/y.png`, name: "y.png", mime: "image/png", ...body }) }), P({ id: wsA }));
      expect((await call({ channelId: foreign.id })).status).toBe(400);
      expect((await call({ channelId: notMine.id })).status).toBe(400);
      expect((await call({ accountId: crypto.randomUUID() })).status).toBe(404);
      expect((await call({ name: "run.exe", mime: "application/x-msdownload" })).status).toBe(415);
    } finally {
      if (prev === undefined) delete process.env.BLOB_READ_WRITE_TOKEN;
      else process.env.BLOB_READ_WRITE_TOKEN = prev;
    }
  });

  it("a persona resource can't pin another workspace's document", async () => {
    const [foreignDoc] = await db().insert(documents).values({ workspaceId: wsB, blobUrl: "", name: "f.txt", mime: "text/plain", uploadedBySub: sub("otherowner") }).returning();
    const id = await addResource(wsA, personaA, { kind: "document", title: "x", documentId: foreignDoc!.id }, sub("vowner"));
    expect(id).toBeNull();
  });
});

describe("mutation hardening — positive paths and edges of the new guards", () => {
  it("persona binding: malformed ids are refused without touching the DB; workspace-wide grants still work", async () => {
    expect(await personaInWorkspace(wsA, "not-a-uuid")).toBe(false);
    expect(await personaInWorkspace(wsA, `${personaA}x`)).toBe(false);
    expect(await personaInWorkspace(wsA, `x${personaA}`)).toBe(false);
    expect(await canConfigurePersona(wsA, sub("vowner"), "Owner", "not-a-uuid")).toBe(false);
    await expect(grantConfig(wsA, sub("alice"), null, sub("vowner"))).resolves.toBeUndefined();
  });

  it("delegated config rights: an internal grantee may configure, an external grantee may not", async () => {
    await grantConfig(wsA, sub("bob"), personaA, sub("vowner"));
    await grantConfig(wsA, sub("partner"), personaA, sub("vowner"));
    expect(await canConfigurePersona(wsA, sub("bob"), "Member", personaA)).toBe(true);
    expect(await canConfigurePersona(wsA, sub("partner"), "Partner", personaA)).toBe(false);
    expect(await canConfigurePersona(wsA, sub("eve"), "Member", personaA)).toBe(false);
  });

  it("persona resources: own document/text/link pin fine; malformed document id is refused cleanly", async () => {
    const [own] = await db().insert(documents).values({ workspaceId: wsA, blobUrl: "", name: "own.txt", mime: "text/plain", uploadedBySub: sub("vowner") }).returning();
    expect(await addResource(wsA, personaA, { kind: "document", title: "d", documentId: own!.id }, sub("vowner"))).toBeTruthy();
    expect(await addResource(wsA, personaA, { kind: "document", title: "d", documentId: "nope" }, sub("vowner"))).toBeNull();
    expect(await addResource(wsA, personaA, { kind: "document", title: "d", documentId: `${own!.id}0` }, sub("vowner"))).toBeNull();
    expect(await addResource(wsA, personaA, { kind: "text", title: "t", content: "hello" }, sub("vowner"))).toBeTruthy();
    expect(await addResource(wsA, personaA, { kind: "link", title: "l", url: "https://example.com" }, sub("vowner"))).toBeTruthy();
  });

  it("calendar item route: a malformed event id is a clean 404, never a DB error", async () => {
    const id = crypto.randomUUID();
    for (const bad of [`${id}x`, `x${id}`, "nope"]) {
      expect((await calEventRoute.GET(req(`/api/workspaces/${wsA}/calendar/${bad}`, "vowner"), P({ id: wsA, eventId: bad }))).status).toBe(404);
    }
  });

  it("download proxy: forbidden body, text-only doc 404, download disposition + no-store", async () => {
    const dm = await createChannel({ workspaceId: wsA, kind: "dm", name: `m-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const [d] = await db().insert(documents).values({ workspaceId: wsA, channelId: dm.id, blobUrl: `https://privstore.private.blob.vercel-storage.com/comms/${wsA}/m.pdf`, name: "m.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    const f = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${d!.id}/download`, "eve"), P({ id: wsA, docId: d!.id }));
    expect(await f.json()).toEqual({ error: "forbidden" });
    const nf = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${crypto.randomUUID()}/download`, "eve"), P({ id: wsA, docId: crypto.randomUUID() }));
    expect(nf.status).toBe(404);
    expect(await nf.json()).toEqual({ error: "not_found" });
    const ok = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${d!.id}/download`, "bob"), P({ id: wsA, docId: d!.id }));
    // Redirects to a signed URL with the download disposition — never the raw store URL.
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toContain("download=1");
    expect(ok.headers.get("location")).not.toContain("blob.vercel-storage.com");
    expect(ok.headers.get("cache-control")).toBe("private, no-store");
    const [t] = await db().insert(documents).values({ workspaceId: wsA, channelId: dm.id, blobUrl: "", name: "gen.md", mime: "text/markdown", uploadedBySub: sub("alice") }).returning();
    expect((await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${t!.id}/download`, "bob"), P({ id: wsA, docId: t!.id }))).status).toBe(404);
  });

  it("MCP: an exhausted request token is 429; an exhausted per-call token refuses that call", async () => {
    limiter.denyPrefix = "mcp:";
    try {
      const r = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "eve", { method: "POST", body: mcpCall("documents.list", { limit: 1 }) }), P({ id: wsA }));
      expect(r.status).toBe(429);
    } finally {
      limiter.denyPrefix = null;
    }
    limiter.denyPrefix = "mcp-call:";
    try {
      const r = await mcpRoute.POST(req(`/api/workspaces/${wsA}/mcp`, "eve", { method: "POST", body: mcpCall("documents.list", { limit: 1 }) }), P({ id: wsA }));
      const j = (await r.json()) as McpResult;
      expect(j.error?.message).toBe("Rate limit exceeded");
      expect(j.result).toBeUndefined();
    } finally {
      limiter.denyPrefix = null;
    }
  });

  it("tags: deals are checked against the deals table; the creator may be listed in memberSubs", async () => {
    const { createAccount, createDeal } = await import("@/lib/domain/crm");
    const { createTag } = await import("@/lib/domain/crm-tags");
    const acct = await createAccount(wsA, `DealParent ${run}`, null, sub("vowner"));
    const deal = await createDeal({ workspaceId: wsA, accountId: acct.id, name: `Deal ${run}`, valueMinor: 100, ownerSub: sub("vowner") });
    const tag = await createTag(wsA, `dtag-${run}`);
    const b = await bulkTagRoute.POST(req(`/api/workspaces/${wsA}/crm/deal/bulk-tag`, "vowner", { method: "POST", body: JSON.stringify({ tagId: tag.id, recordIds: [deal.id, acct.id] }) }), P({ id: wsA, entity: "deal" }));
    expect(((await b.json()) as { tagged: number }).tagged).toBe(1);
    const ch = await createChannel({ workspaceId: wsA, kind: "channel", name: `self-${run}`, createdBySub: sub("vowner"), memberSubs: [sub("vowner"), sub("alice")] });
    const seats = (await db().select().from(channelMembers).where(eq(channelMembers.channelId, ch.id))).map((x) => x.sub).sort();
    expect(seats).toEqual([sub("alice"), sub("vowner")].sort());
  });

  it("acceptInvite: existing active member keeps role; offboarded member is reactivated; a foreign-workspace scope is never seated", async () => {
    const { members } = await import("@/lib/db/schema");
    const i1 = await createInvite({ workspaceId: wsA, email: `own-${run}@example.com`, role: "Guest", invitedBySub: sub("vowner") });
    const a1 = await acceptInvite({ token: i1.token, sub: sub("vowner") });
    expect(a1).toEqual({ ok: true, workspaceId: wsA, alreadyMember: true });
    const [owner] = await db().select().from(members).where(and(eq(members.workspaceId, wsA), eq(members.sub, sub("vowner"))));
    expect(owner!.role).toBe("Owner");

    await addMember(wsA, "gone", "Member");
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, wsA), eq(members.sub, sub("gone"))));
    const i2 = await createInvite({ workspaceId: wsA, email: `back-${run}@example.com`, role: "Guest", invitedBySub: sub("vowner") });
    const a2 = await acceptInvite({ token: i2.token, sub: sub("gone") });
    expect(a2).toEqual({ ok: true, workspaceId: wsA, alreadyMember: false });
    const [g] = await db().select().from(members).where(and(eq(members.workspaceId, wsA), eq(members.sub, sub("gone"))));
    expect([g!.status, g!.role]).toEqual(["active", "Guest"]);

    const foreign = await createChannel({ workspaceId: wsB, kind: "channel", name: `fs-${run}`, createdBySub: sub("otherowner") });
    const token = `directrow-${run}`;
    await db().insert(invites).values({ tokenHash: hashToken(token), workspaceId: wsA, email: `f-${run}@example.com`, role: "Guest", scopeChannelId: foreign.id, invitedBySub: sub("vowner"), expiresAt: new Date(Date.now() + 3600_000) });
    expect((await acceptInvite({ token, sub: sub("scopedinvitee") })).ok).toBe(true);
    expect(await db().select().from(channelMembers).where(eq(channelMembers.sub, sub("scopedinvitee")))).toHaveLength(0);
    expect((await acceptInvite({ token, sub: sub("scopedinvitee2") })).ok).toBe(false);
  });
});

describe("PBA-L3c-002: an invite scope can never grant access the inviter lacks", () => {
  it("routes refuse a DM scope and a channel the inviter isn't seated in (single + batch)", async () => {
    await addMember(wsA, "adm2", "Admin");
    for (const n of ["alice", "bob"]) await addMember(wsA, n, "Member").catch(() => undefined); // tolerate -t isolation
    const dm = await createChannel({ workspaceId: wsA, kind: "dm", name: `vd-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const priv = await createChannel({ workspaceId: wsA, kind: "channel", name: `priv-${run}`, createdBySub: sub("alice") });
    for (const scope of [dm.id, priv.id]) {
      const r = await invitesRoute.POST(req(`/api/workspaces/${wsA}/invites`, "adm2", { method: "POST", body: JSON.stringify({ workspaceId: wsA, email: `adm2-${run}@example.com`, role: "Member", scopeChannelId: scope }) }), P({ id: wsA }));
      expect(r.status).toBe(400);
      const b = await inviteBatchRoute.POST(req(`/api/workspaces/${wsA}/invites/batch`, "adm2", { method: "POST", body: JSON.stringify({ workspaceId: wsA, emails: [`batch-${run}@example.com`], role: "Guest", scopeChannelId: scope }) }), P({ id: wsA }));
      expect(b.status).toBe(400);
    }
    // even a SEATED inviter can't scope to a DM
    await expect(createInvite({ workspaceId: wsA, email: `d-${run}@example.com`, role: "Guest", invitedBySub: sub("alice"), scopeChannelId: dm.id })).rejects.toThrow(/scope channel/);
  });

  it("redemption never seats an existing member, and re-checks that the inviter is still seated", async () => {
    await addMember(wsA, "admseat", "Admin"); // the inviter must hold AddMember
    const ch = await createChannel({ workspaceId: wsA, kind: "channel", name: `room-${run}`, createdBySub: sub("admseat") });
    await addMember(wsA, "existing2", "Member"); // self-contained: an already-active member
    const i1 = await createInvite({ workspaceId: wsA, email: `e-${run}@example.com`, role: "Member", invitedBySub: sub("admseat"), scopeChannelId: ch.id });
    expect(await acceptInvite({ token: i1.token, sub: sub("existing2") })).toMatchObject({ ok: true, alreadyMember: true });
    expect(await db().select().from(channelMembers).where(and(eq(channelMembers.channelId, ch.id), eq(channelMembers.sub, sub("existing2"))))).toHaveLength(0);

    const i2 = await createInvite({ workspaceId: wsA, email: `n-${run}@example.com`, role: "Guest", invitedBySub: sub("admseat"), scopeChannelId: ch.id });
    await db().delete(channelMembers).where(and(eq(channelMembers.channelId, ch.id), eq(channelMembers.sub, sub("admseat"))));
    expect((await acceptInvite({ token: i2.token, sub: sub("newguest") })).ok).toBe(true);
    expect(await db().select().from(channelMembers).where(eq(channelMembers.sub, sub("newguest")))).toHaveLength(0);
  });
});
