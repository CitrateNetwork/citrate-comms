/**
 * PBA-R2 security regression suite — the pre-bounty audit's authz PoC
 * (audits/2026-09-24-prebounty-adversarial-audit/lanes/L3c-public-web-apps/evidence/comms/
 * authz.int.test.ts, SEC-1..SEC-6) ported into the repo with every assertion INVERTED:
 * each exploit that passed against 7a08fba must now be refused.
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
import { crmRecordTags } from "@/lib/db/schema";
import { run, sub, req, P, addMember, mcpCall } from "./helpers";

type McpResult = { result?: { isError?: boolean; structuredContent?: Record<string, unknown>; tools?: { name: string }[] }; error?: { code: number; message: string } };

let victimWs: string, attackerWs: string;
let victimPersonaId: string;

beforeAll(async () => {
  victimWs = (await createWorkspace({ name: `victim ${run}`, ownerSub: sub("vowner"), ownerWallet: null, ownerEmail: null })).id;
  attackerWs = (await createWorkspace({ name: `attacker ${run}`, ownerSub: sub("mallory"), ownerWallet: null, ownerEmail: null })).id;
  await seedDefaultPersonas(victimWs, sub("vowner"));
  await seedDefaultPersonas(attackerWs, sub("mallory"));
  victimPersonaId = (await listPersonas(victimWs))[0]!.id;
});

describe("PBA-L3c-001 persona config is bound to its workspace (SEC-1 inverted)", () => {
  it("an Owner of ANOTHER workspace cannot overwrite the victim persona's prompt layer", async () => {
    let r = await promptsRoute.POST(req(`/api/workspaces/${victimWs}/personas/${victimPersonaId}/prompts`, "vowner", { method: "POST", body: JSON.stringify({ layer: 1, content: "VICTIM MISSION" }) }), P({ id: victimWs, personaId: victimPersonaId }));
    expect(r.status).toBe(200);
    expect((await resolvePersona(victimWs, victimPersonaId))!.overrides.mission).toBe("VICTIM MISSION");

    r = await promptsRoute.POST(req(`/api/workspaces/${attackerWs}/personas/${victimPersonaId}/prompts`, "mallory", { method: "POST", body: JSON.stringify({ layer: 1, content: "ATTACKER" }) }), P({ id: attackerWs, personaId: victimPersonaId }));
    expect(r.status).toBe(403);

    const [row] = await db().select().from(agentPrompts).where(and(eq(agentPrompts.personaId, victimPersonaId), eq(agentPrompts.layer, 1)));
    expect(row!.workspaceId).toBe(victimWs);
    expect(row!.updatedBySub).toBe(sub("vowner"));
    expect((await resolvePersona(victimWs, victimPersonaId))!.overrides.mission).toBe("VICTIM MISSION");
  });

  it("an Owner of another workspace cannot toggle the victim persona's skills", async () => {
    await setSkillEnabled(victimWs, victimPersonaId, "pba-probe", true);
    const [s] = await db().select().from(agentSkills).where(and(eq(agentSkills.personaId, victimPersonaId), eq(agentSkills.skillKey, "pba-probe")));
    const r = await skillsRoute.POST(req(`/api/workspaces/${attackerWs}/personas/${victimPersonaId}/skills`, "mallory", { method: "POST", body: JSON.stringify({ skillKey: s!.skillKey, enabled: false }) }), P({ id: attackerWs, personaId: victimPersonaId }));
    expect(r.status).toBe(403);
    const [after] = await db().select().from(agentSkills).where(eq(agentSkills.id, s!.id));
    expect(after!.enabled).toBe(true);
  });

  it("cross-tenant persona read/patch/resources/grant are refused", async () => {
    const g = await personaRoute.GET(req(`/api/workspaces/${attackerWs}/personas/${victimPersonaId}`, "mallory"), P({ id: attackerWs, personaId: victimPersonaId }));
    expect(g.status).toBe(403);
    const pa = await personaRoute.PATCH(req(`/api/workspaces/${attackerWs}/personas/${victimPersonaId}`, "mallory", { method: "PATCH", body: JSON.stringify({ enabled: false }) }), P({ id: attackerWs, personaId: victimPersonaId }));
    expect(pa.status).toBe(403);
    const rs = await resourcesRoute.POST(req(`/api/workspaces/${attackerWs}/personas/${victimPersonaId}/resources`, "mallory", { method: "POST", body: JSON.stringify({ kind: "text", title: "x", content: "inject" }) }), P({ id: attackerWs, personaId: victimPersonaId }));
    expect(rs.status).toBe(403);
    const gr = await grantsRoute.POST(req(`/api/workspaces/${attackerWs}/persona-config-grants`, "mallory", { method: "POST", body: JSON.stringify({ granteeSub: sub("mallory"), personaId: victimPersonaId }) }), P({ id: attackerWs }));
    expect(gr.status).toBe(403);
    expect(await db().select().from(agentResources).where(eq(agentResources.personaId, victimPersonaId))).toHaveLength(0);
    expect(await db().select().from(agentConfigGrants).where(eq(agentConfigGrants.personaId, victimPersonaId))).toHaveLength(0);
  });

  it("domain layer refuses a foreign persona even if a route forgot to check", async () => {
    await expect(setPromptLayer(attackerWs, victimPersonaId, 2, "x", sub("mallory"))).rejects.toThrow(/persona not in this workspace/);
    await expect(setSkillEnabled(attackerWs, victimPersonaId, "pba-probe", false)).rejects.toThrow(/persona not in this workspace/);
    await expect(addResource(attackerWs, victimPersonaId, { kind: "text", title: "t", content: "c" }, sub("mallory"))).rejects.toThrow(/persona not in this workspace/);
    await expect(grantConfig(attackerWs, sub("mallory"), victimPersonaId, sub("mallory"))).rejects.toThrow(/persona not in this workspace/);
    expect(await canConfigurePersona(attackerWs, sub("mallory"), "Owner", victimPersonaId)).toBe(false);
    expect(await canConfigurePersona(victimWs, sub("vowner"), "Owner", victimPersonaId)).toBe(true);
  });

  it("a pre-planted cross-tenant row is never rewritten by the victim's upsert (setWhere)", async () => {
    // Simulate a row planted before the fix: attacker-workspace row on the victim persona.
    const planted = (await listPersonas(victimWs))[1]!.id;
    await db().insert(agentPrompts).values({ workspaceId: attackerWs, personaId: planted, layer: 3, contentEnc: encryptField(attackerWs, "PLANT"), updatedBySub: sub("mallory") }).catch(() => undefined);
    const [before] = await db().select().from(agentPrompts).where(and(eq(agentPrompts.personaId, planted), eq(agentPrompts.layer, 3)));
    if (!before) return; // migration 0016's composite FK refused the plant outright — stronger still
    await setPromptLayer(victimWs, planted, 3, "victim", sub("vowner"));
    const [after] = await db().select().from(agentPrompts).where(and(eq(agentPrompts.personaId, planted), eq(agentPrompts.layer, 3)));
    expect(after!.workspaceId).toBe(attackerWs);
    expect(after!.updatedBySub).toBe(sub("mallory"));
  });
});

describe("PBA-L3c-003 private-channel / DM attachments stay private (SEC-3 inverted)", () => {
  let dmDocId: string;
  let wsDocId: string;
  beforeAll(async () => {
    await addMember(victimWs, "alice", "Member");
    await addMember(victimWs, "bob", "Member");
    await addMember(victimWs, "eve", "Member");
    await addMember(victimWs, "guest", "Guest");
    const dm = await createChannel({ workspaceId: victimWs, kind: "dm", name: "alice-bob", createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const [d] = await db().insert(documents).values({ workspaceId: victimWs, channelId: dm.id, blobUrl: "https://x.public.blob.vercel-storage.com/offer-letter-bob.pdf", name: "offer-letter-bob.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    dmDocId = d!.id;
    await db().insert(documentChunks).values({ workspaceId: victimWs, documentId: dmDocId, ord: 0, textEnc: encryptField(victimWs, "compensation offer salary bob confidential") });
    const [w] = await db().insert(documents).values({ workspaceId: victimWs, blobUrl: "https://x.public.blob.vercel-storage.com/handbook.pdf", name: "handbook.pdf", mime: "application/pdf", uploadedBySub: sub("vowner") }).returning();
    wsDocId = w!.id;
    await db().insert(documentChunks).values({ workspaceId: victimWs, documentId: wsDocId, ord: 0, textEnc: encryptField(victimWs, "compensation policy handbook") });
  });

  const mcp = async (who: string, name: string, args: Record<string, unknown>) =>
    (await (await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, who, { method: "POST", body: mcpCall(name, args) }), P({ id: victimWs }))).json()) as McpResult;

  it("Guest cannot use documents.list at all (external role, deny by default)", async () => {
    const j = await mcp("guest", "documents.list", { limit: 50 });
    expect(j.error?.message ?? "").toMatch(/Unknown tool/);
    expect(JSON.stringify(j)).not.toContain(dmDocId);
  });

  it("Eve (not in the alice-bob DM) is refused the DM attachment download; bob gets it", async () => {
    const r = await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${dmDocId}/download`, "eve"), P({ id: victimWs, docId: dmDocId }));
    expect(r.status).toBe(403);
    expect(r.headers.get("location")).toBeNull();
    const ok = await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${dmDocId}/download`, "bob"), P({ id: victimWs, docId: dmDocId }));
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
    const ch = await createChannel({ workspaceId: victimWs, kind: "channel", name: `shared-${run}`, createdBySub: sub("alice"), memberSubs: [sub("guest")] });
    const [d] = await db().insert(documents).values({ workspaceId: victimWs, channelId: ch.id, blobUrl: "https://x.public.blob.vercel-storage.com/shared.pdf", name: "shared.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    expect((await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${d!.id}/download`, "guest"), P({ id: victimWs, docId: d!.id }))).status).toBe(302);
    expect((await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${wsDocId}/download`, "guest"), P({ id: victimWs, docId: wsDocId }))).status).toBe(403);
    expect((await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${dmDocId}/download`, "guest"), P({ id: victimWs, docId: dmDocId }))).status).toBe(403);
  });
});

describe("PBA-L3c-002 Partner/Guest are scoped to their channels (SEC-4 inverted)", () => {
  beforeAll(async () => {
    await addMember(victimWs, "partner", "Partner");
    const { createAccount } = await import("@/lib/domain/crm");
    await createAccount(victimWs, "Acme Secret Prospect", "acme.example", sub("vowner"));
  });

  it("external Partner gets 403 on the account list; a Member still reads it", async () => {
    const r = await accountsRoute.GET(req(`/api/workspaces/${victimWs}/accounts`, "partner"), P({ id: victimWs }));
    expect(r.status).toBe(403);
    expect(JSON.stringify(await r.json())).not.toContain("Acme Secret Prospect");
    const m = await accountsRoute.GET(req(`/api/workspaces/${victimWs}/accounts`, "eve"), P({ id: victimWs }));
    expect(m.status).toBe(200);
    expect(JSON.stringify(await m.json())).toContain("Acme Secret Prospect");
  });

  it("Guest/Partner MCP surface lists only channel-scoped tools; crm.read is unknown to them", async () => {
    for (const who of ["guest", "partner"]) {
      const r = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, who, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }), P({ id: victimWs }));
      const names = ((await r.json()) as McpResult).result!.tools!.map((t) => t.name);
      expect(names).toEqual(["thread.summarize"]);
      const c = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, who, { method: "POST", body: mcpCall("crm.read", { entity: "account" }) }), P({ id: victimWs }));
      const txt = JSON.stringify(await c.json());
      expect(txt).not.toContain("Acme Secret Prospect");
      expect(txt).toMatch(/Unknown tool/);
    }
  });

  it("calendar: a non-attendee Guest cannot read an event by id; Partner MCP calendar.read is unavailable", async () => {
    const start = new Date(Date.now() + 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: victimWs, kind: "meeting", titleEnc: encryptField(victimWs, "Layoff planning (HR only)"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: victimWs, eventId: ev!.id, sub: sub("alice") } as never);
    const r1 = await calEventRoute.GET(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "guest"), P({ id: victimWs, eventId: ev!.id }));
    expect([403, 404]).toContain(r1.status);
    expect(JSON.stringify(await r1.json())).not.toContain("Layoff planning");
    const r2 = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "partner", { method: "POST", body: mcpCall("calendar.read", {}) }), P({ id: victimWs }));
    expect(JSON.stringify(await r2.json())).not.toContain("Layoff planning");
  });

  it("a Partner cannot drive the agent chat (which would read CRM as role=Agent)", async () => {
    const pid = (await listPersonas(victimWs))[0]!.id;
    const r = await agentChatRoute.POST(req(`/api/workspaces/${victimWs}/agents/${pid}/chat`, "partner", { method: "POST", body: JSON.stringify({ messages: [{ role: "user", parts: [{ type: "text", text: "list accounts" }] }] }) }), P({ id: victimWs, agentId: pid }));
    expect(r.status).toBe(403);
  });

  it("a Partner invite scoped to a channel seats the partner in exactly that channel", async () => {
    const ch = await createChannel({ workspaceId: victimWs, kind: "channel", name: `deal-room-${run}`, createdBySub: sub("vowner") });
    const inv = await createInvite({ workspaceId: victimWs, email: `p-${run}@example.com`, role: "Partner", invitedBySub: sub("vowner"), scopeChannelId: ch.id });
    const res = await acceptInvite({ token: inv.token, sub: sub("partner2") });
    expect(res.ok).toBe(true);
    const seats = await db().select().from(channelMembers).where(eq(channelMembers.sub, sub("partner2")));
    expect(seats.map((s) => s.channelId)).toEqual([ch.id]);
    const { members } = await import("@/lib/db/schema");
    const [m] = await db().select().from(members).where(and(eq(members.workspaceId, victimWs), eq(members.sub, sub("partner2"))));
    expect([m?.role, m?.status]).toEqual(["Partner", "active"]);
    const foreign = await createChannel({ workspaceId: attackerWs, kind: "channel", name: "x", createdBySub: sub("mallory") });
    await expect(createInvite({ workspaceId: victimWs, email: `q-${run}@example.com`, role: "Partner", invitedBySub: sub("vowner"), scopeChannelId: foreign.id })).rejects.toThrow(/scope channel/);
  });
});

describe("PBA-L3c-005 message attachments must be the workspace's (and visible) documents (SEC-2 inverted)", () => {
  it("linking a document id from ANOTHER workspace is rejected with 400 and nothing is linked", async () => {
    const [doc] = await db().insert(documents).values({ workspaceId: victimWs, blobUrl: "https://x.public.blob.vercel-storage.com/secret-board-deck-abc.pdf", name: "Board deck Q3 (CONFIDENTIAL).pdf", mime: "application/pdf", uploadedBySub: sub("vowner") }).returning();
    const ch = await createChannel({ workspaceId: attackerWs, kind: "channel", name: "x", createdBySub: sub("mallory") });
    const r = await msgRoute.POST(req(`/api/channels/${ch.id}/messages`, "mallory", { method: "POST", body: JSON.stringify({ body: "", attachmentIds: [doc!.id] }) }), P({ id: ch.id }));
    expect(r.status).toBe(400);
    expect(JSON.stringify(await r.json())).not.toContain("secret-board-deck");
    expect(await db().select().from(messageAttachments).where(eq(messageAttachments.documentId, doc!.id))).toHaveLength(0);
  });

  it("a member cannot re-share a DM attachment they cannot see into a channel", async () => {
    const dm = await createChannel({ workspaceId: victimWs, kind: "dm", name: "a-b-2", createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const [d] = await db().insert(documents).values({ workspaceId: victimWs, channelId: dm.id, blobUrl: "https://x.public.blob.vercel-storage.com/p.pdf", name: "p.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    const pub = await createChannel({ workspaceId: victimWs, kind: "channel", name: `pub-${run}`, createdBySub: sub("vowner"), memberSubs: [sub("eve")] });
    const r = await msgRoute.POST(req(`/api/channels/${pub.id}/messages`, "eve", { method: "POST", body: JSON.stringify({ body: "", attachmentIds: [d!.id] }) }), P({ id: pub.id }));
    expect(r.status).toBe(400);
  });
});

describe("PBA-L3c-009 clients never receive raw Blob URLs; finalize is pinned to this store", () => {
  it("a message attachment is served as the access-controlled inline proxy URL", async () => {
    const ch = await createChannel({ workspaceId: victimWs, kind: "channel", name: `att-${run}`, createdBySub: sub("alice") });
    const [d] = await db().insert(documents).values({ workspaceId: victimWs, channelId: ch.id, blobUrl: "https://store1.public.blob.vercel-storage.com/diagram.png", name: "diagram.png", mime: "image/png", uploadedBySub: sub("alice") }).returning();
    const r = await msgRoute.POST(req(`/api/channels/${ch.id}/messages`, "alice", { method: "POST", body: JSON.stringify({ body: "see", attachmentIds: [d!.id] }) }), P({ id: ch.id }));
    expect(r.status).toBe(201);
    const j = (await r.json()) as { message: { attachments: { url: string }[] } };
    expect(j.message.attachments[0]!.url).toBe(`/api/workspaces/${victimWs}/documents/${d!.id}/download?inline=1`);
    expect(JSON.stringify(j)).not.toContain("blob.vercel-storage.com");
    // inline view: same authorization as a download
    expect((await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${d!.id}/download?inline=1`, "eve"), P({ id: victimWs, docId: d!.id }))).status).toBe(403);
    const ok = await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${d!.id}/download?inline=1`, "alice"), P({ id: victimWs, docId: d!.id }));
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).not.toContain("download=1");
  });

  it("finalize refuses a Blob URL from any store other than this deployment's", async () => {
    const prev = process.env.BLOB_READ_WRITE_TOKEN;
    process.env.BLOB_READ_WRITE_TOKEN = "vercel_blob_rw_Store1_testsecret";
    try {
      const bad = await finalizeRoute.POST(req(`/api/workspaces/${victimWs}/documents/finalize`, "alice", { method: "POST", body: JSON.stringify({ blobUrl: "https://attacker9.public.blob.vercel-storage.com/x.png", name: "x.png", mime: "image/png" }) }), P({ id: victimWs }));
      expect(bad.status).toBe(400);
      expect(await bad.json()).toMatchObject({ error: "bad_host" });
      const good = await finalizeRoute.POST(req(`/api/workspaces/${victimWs}/documents/finalize`, "alice", { method: "POST", body: JSON.stringify({ blobUrl: "https://store1.public.blob.vercel-storage.com/x.png", name: "x.png", mime: "image/png" }) }), P({ id: victimWs }));
      expect(good.status).toBe(201);
    } finally {
      if (prev === undefined) delete process.env.BLOB_READ_WRITE_TOKEN;
      else process.env.BLOB_READ_WRITE_TOKEN = prev;
    }
  });
});

describe("PBA-L3c-007 calendar events: creator/attendees read, creator/admin edit (SEC-4 inverted)", () => {
  it("a Member who is not an attendee cannot read, edit or cancel someone else's event", async () => {
    const start = new Date(Date.now() + 2 * 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: victimWs, kind: "meeting", titleEnc: encryptField(victimWs, "1:1 alice/bob"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: victimWs, eventId: ev!.id, sub: sub("bob") } as never);
    const g = await calEventRoute.GET(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "eve"), P({ id: victimWs, eventId: ev!.id }));
    expect(g.status).toBe(404);
    // a non-attendee can't even see it, so a write is "not found" (no existence oracle)
    const p = await calEventRoute.PATCH(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "eve", { method: "PATCH", body: JSON.stringify({ title: "pwn" }) }), P({ id: victimWs, eventId: ev!.id }));
    expect(p.status).toBe(404);
    const d = await calEventRoute.DELETE(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "eve", { method: "DELETE" }), P({ id: victimWs, eventId: ev!.id }));
    expect(d.status).toBe(404);
    const [still] = await db().select().from(calendarEvents).where(eq(calendarEvents.id, ev!.id));
    expect(still!.status).not.toBe("cancelled");
    // attendee reads; attendee (non-creator Member) may not edit; creator edits; Owner cancels
    expect((await calEventRoute.GET(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "bob"), P({ id: victimWs, eventId: ev!.id }))).status).toBe(200);
    expect((await calEventRoute.PATCH(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "bob", { method: "PATCH", body: JSON.stringify({ title: "x" }) }), P({ id: victimWs, eventId: ev!.id }))).status).toBe(403);
    expect((await calEventRoute.PATCH(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "alice", { method: "PATCH", body: JSON.stringify({ title: "1:1 moved" }) }), P({ id: victimWs, eventId: ev!.id }))).status).toBe(200);
    expect((await calEventRoute.GET(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "vowner"), P({ id: victimWs, eventId: ev!.id }))).status).toBe(200);
    expect((await calEventRoute.DELETE(req(`/api/workspaces/${victimWs}/calendar/${ev!.id}`, "vowner", { method: "DELETE" }), P({ id: victimWs, eventId: ev!.id }))).status).toBe(200);
  });

  it("calendar.read (MCP) shows a non-attended event as busy only (no title) to a Member", async () => {
    const start = new Date(Date.now() + 3 * 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: victimWs, kind: "meeting", titleEnc: encryptField(victimWs, "Board: acquisition talks"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("alice"), timezone: "UTC" } as never).returning();
    const r = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "eve", { method: "POST", body: mcpCall("calendar.read", {}) }), P({ id: victimWs }));
    const txt = JSON.stringify(await r.json());
    expect(txt).not.toContain("acquisition talks");
    expect(txt).toContain("busy");
    const own = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "alice", { method: "POST", body: mcpCall("calendar.read", {}) }), P({ id: victimWs }));
    expect(JSON.stringify(await own.json())).toContain("acquisition talks");
    expect(ev).toBeTruthy();
  });
});

describe("PBA-L3c-020 ledger PATCH is scoped to the route's channel (SEC-5 inverted)", () => {
  it("a member of channel A cannot resolve a commitment in private channel B", async () => {
    const a = await createChannel({ workspaceId: victimWs, kind: "channel", name: "a", createdBySub: sub("vowner"), memberSubs: [sub("eve")] });
    const b = await createChannel({ workspaceId: victimWs, kind: "channel", name: "b", createdBySub: sub("vowner"), memberSubs: [sub("alice")] });
    const entry = await witness({ workspaceId: victimWs, channelId: b.id, kind: "commitment", text: "ship", bySub: sub("alice") });
    const r = await ledgerRoute.PATCH(req(`/api/channels/${a.id}/ledger`, "eve", { method: "PATCH", body: JSON.stringify({ entryId: entry.id }) }), P({ id: a.id }));
    expect(r.status).toBe(404);
    const [row] = await db().select().from(ledgerEntries).where(eq(ledgerEntries.id, entry.id));
    expect(row!.status).not.toBe("done");
    const ok = await ledgerRoute.PATCH(req(`/api/channels/${b.id}/ledger`, "alice", { method: "PATCH", body: JSON.stringify({ entryId: entry.id }) }), P({ id: b.id }));
    expect(ok.status).toBe(200);
  });
});

describe("PBA-L3c-006 MCP batches are bounded and every call is charged (SEC-6 inverted)", () => {
  it("a 300-call batch is rejected before any tool runs", async () => {
    const batch = Array.from({ length: 300 }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "documents.list", arguments: { limit: 1 } } }));
    const r = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "eve", { method: "POST", body: JSON.stringify(batch) }), P({ id: victimWs }));
    expect(r.status).toBe(400);
  });

  it("each tools/call in an allowed batch consumes its own rate-limit token", async () => {
    limitCalls.length = 0;
    const batch = Array.from({ length: 5 }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "documents.list", arguments: { limit: 1 } } }));
    const r = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "eve", { method: "POST", body: JSON.stringify(batch) }), P({ id: victimWs }));
    expect(r.status).toBe(200);
    expect(((await r.json()) as unknown[]).length).toBe(5);
    expect(limitCalls.filter((k) => k.startsWith("mcp")).length).toBeGreaterThanOrEqual(1 + 5);
  });
});

describe("PBA-L3c-023 invite single-use consume is atomic", () => {
  it("two concurrent accepts of one token admit exactly one identity", async () => {
    const inv = await createInvite({ workspaceId: victimWs, email: `race-${run}@example.com`, role: "Member", invitedBySub: sub("vowner") });
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
    const mine = await createAccount(victimWs, `Tagged ${run}`, null, sub("vowner"));
    const foreignAcct = await createAccount(attackerWs, `Foreign ${run}`, null, sub("mallory"));
    const foreignTag = await createTag(attackerWs, `ftag-${run}`);
    const r = await tagsRoute.POST(req(`/api/workspaces/${victimWs}/crm/account/${mine.id}/tags`, "vowner", { method: "POST", body: JSON.stringify({ tagId: foreignTag.id }) }), P({ id: victimWs, entity: "account", recordId: mine.id }));
    expect(r.status).toBe(403);
    const ownTag = await createTag(victimWs, `vtag-${run}`);
    const b = await bulkTagRoute.POST(req(`/api/workspaces/${victimWs}/crm/account/bulk-tag`, "vowner", { method: "POST", body: JSON.stringify({ tagId: ownTag.id, recordIds: [mine.id, foreignAcct.id, crypto.randomUUID()] }) }), P({ id: victimWs, entity: "account" }));
    expect(b.status).toBe(200);
    expect(((await b.json()) as { tagged: number }).tagged).toBe(1);
    const links = await db().select().from(crmRecordTags).where(eq(crmRecordTags.workspaceId, victimWs));
    expect(links.map((l) => l.recordId)).not.toContain(foreignAcct.id);
    expect(links.map((l) => l.tagId)).not.toContain(foreignTag.id);
  });

  it("a channel only seats active members of its own workspace", async () => {
    const r = await channelsRoute.POST(req(`/api/channels`, "vowner", { method: "POST", body: JSON.stringify({ workspaceId: victimWs, kind: "channel", name: `seat-${run}`, memberSubs: [sub("alice"), sub("mallory"), "dev:nobody"] }) }));
    expect(r.status).toBe(201);
    const { channel } = (await r.json()) as { channel: { id: string } };
    const seats = (await db().select().from(channelMembers).where(eq(channelMembers.channelId, channel.id))).map((x) => x.sub).sort();
    expect(seats).toEqual([sub("alice"), sub("vowner")].sort());
  });

  it("finalize refuses a foreign channel scope, a channel the uploader isn't in, and a disallowed type", async () => {
    const prev = process.env.BLOB_READ_WRITE_TOKEN;
    process.env.BLOB_READ_WRITE_TOKEN = "vercel_blob_rw_Store1_testsecret";
    try {
      const foreign = await createChannel({ workspaceId: attackerWs, kind: "channel", name: "f", createdBySub: sub("mallory") });
      const notMine = await createChannel({ workspaceId: victimWs, kind: "channel", name: `nm-${run}`, createdBySub: sub("bob") });
      const call = (body: Record<string, unknown>) => finalizeRoute.POST(req(`/api/workspaces/${victimWs}/documents/finalize`, "alice", { method: "POST", body: JSON.stringify({ blobUrl: "https://store1.public.blob.vercel-storage.com/y.png", name: "y.png", mime: "image/png", ...body }) }), P({ id: victimWs }));
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
    const [foreignDoc] = await db().insert(documents).values({ workspaceId: attackerWs, blobUrl: "", name: "f.txt", mime: "text/plain", uploadedBySub: sub("mallory") }).returning();
    const id = await addResource(victimWs, victimPersonaId, { kind: "document", title: "x", documentId: foreignDoc!.id }, sub("vowner"));
    expect(id).toBeNull();
  });
});

describe("mutation hardening — positive paths and edges of the new guards", () => {
  it("persona binding: malformed ids are refused without touching the DB; workspace-wide grants still work", async () => {
    expect(await personaInWorkspace(victimWs, "not-a-uuid")).toBe(false);
    expect(await personaInWorkspace(victimWs, `${victimPersonaId}x`)).toBe(false);
    expect(await personaInWorkspace(victimWs, `x${victimPersonaId}`)).toBe(false);
    expect(await canConfigurePersona(victimWs, sub("vowner"), "Owner", "not-a-uuid")).toBe(false);
    await expect(grantConfig(victimWs, sub("alice"), null, sub("vowner"))).resolves.toBeUndefined();
  });

  it("delegated config rights: an internal grantee may configure, an external grantee may not", async () => {
    await grantConfig(victimWs, sub("bob"), victimPersonaId, sub("vowner"));
    await grantConfig(victimWs, sub("partner"), victimPersonaId, sub("vowner"));
    expect(await canConfigurePersona(victimWs, sub("bob"), "Member", victimPersonaId)).toBe(true);
    expect(await canConfigurePersona(victimWs, sub("partner"), "Partner", victimPersonaId)).toBe(false);
    expect(await canConfigurePersona(victimWs, sub("eve"), "Member", victimPersonaId)).toBe(false);
  });

  it("persona resources: own document/text/link pin fine; malformed document id is refused cleanly", async () => {
    const [own] = await db().insert(documents).values({ workspaceId: victimWs, blobUrl: "", name: "own.txt", mime: "text/plain", uploadedBySub: sub("vowner") }).returning();
    expect(await addResource(victimWs, victimPersonaId, { kind: "document", title: "d", documentId: own!.id }, sub("vowner"))).toBeTruthy();
    expect(await addResource(victimWs, victimPersonaId, { kind: "document", title: "d", documentId: "nope" }, sub("vowner"))).toBeNull();
    expect(await addResource(victimWs, victimPersonaId, { kind: "document", title: "d", documentId: `${own!.id}0` }, sub("vowner"))).toBeNull();
    expect(await addResource(victimWs, victimPersonaId, { kind: "text", title: "t", content: "hello" }, sub("vowner"))).toBeTruthy();
    expect(await addResource(victimWs, victimPersonaId, { kind: "link", title: "l", url: "https://example.com" }, sub("vowner"))).toBeTruthy();
  });

  it("calendar item route: a malformed event id is a clean 404, never a DB error", async () => {
    const id = crypto.randomUUID();
    for (const bad of [`${id}x`, `x${id}`, "nope"]) {
      expect((await calEventRoute.GET(req(`/api/workspaces/${victimWs}/calendar/${bad}`, "vowner"), P({ id: victimWs, eventId: bad }))).status).toBe(404);
    }
  });

  it("download proxy: forbidden body, text-only doc 404, download disposition + no-store", async () => {
    const dm = await createChannel({ workspaceId: victimWs, kind: "dm", name: `m-${run}`, createdBySub: sub("alice"), memberSubs: [sub("bob")] });
    const [d] = await db().insert(documents).values({ workspaceId: victimWs, channelId: dm.id, blobUrl: "https://store1.public.blob.vercel-storage.com/m.pdf", name: "m.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    const f = await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${d!.id}/download`, "eve"), P({ id: victimWs, docId: d!.id }));
    expect(await f.json()).toEqual({ error: "forbidden" });
    const nf = await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${crypto.randomUUID()}/download`, "eve"), P({ id: victimWs, docId: crypto.randomUUID() }));
    expect(nf.status).toBe(404);
    expect(await nf.json()).toEqual({ error: "not_found" });
    const ok = await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${d!.id}/download`, "bob"), P({ id: victimWs, docId: d!.id }));
    expect(ok.headers.get("location")).toBe("https://store1.public.blob.vercel-storage.com/m.pdf?download=1");
    expect(ok.headers.get("cache-control")).toBe("private, no-store");
    const [t] = await db().insert(documents).values({ workspaceId: victimWs, channelId: dm.id, blobUrl: "", name: "gen.md", mime: "text/markdown", uploadedBySub: sub("alice") }).returning();
    expect((await dlRoute.GET(req(`/api/workspaces/${victimWs}/documents/${t!.id}/download`, "bob"), P({ id: victimWs, docId: t!.id }))).status).toBe(404);
  });

  it("MCP: an exhausted request token is 429; an exhausted per-call token refuses that call", async () => {
    limiter.denyPrefix = "mcp:";
    try {
      const r = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "eve", { method: "POST", body: mcpCall("documents.list", { limit: 1 }) }), P({ id: victimWs }));
      expect(r.status).toBe(429);
    } finally {
      limiter.denyPrefix = null;
    }
    limiter.denyPrefix = "mcp-call:";
    try {
      const r = await mcpRoute.POST(req(`/api/workspaces/${victimWs}/mcp`, "eve", { method: "POST", body: mcpCall("documents.list", { limit: 1 }) }), P({ id: victimWs }));
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
    const acct = await createAccount(victimWs, `DealParent ${run}`, null, sub("vowner"));
    const deal = await createDeal({ workspaceId: victimWs, accountId: acct.id, name: `Deal ${run}`, valueMinor: 100, ownerSub: sub("vowner") });
    const tag = await createTag(victimWs, `dtag-${run}`);
    const b = await bulkTagRoute.POST(req(`/api/workspaces/${victimWs}/crm/deal/bulk-tag`, "vowner", { method: "POST", body: JSON.stringify({ tagId: tag.id, recordIds: [deal.id, acct.id] }) }), P({ id: victimWs, entity: "deal" }));
    expect(((await b.json()) as { tagged: number }).tagged).toBe(1);
    const ch = await createChannel({ workspaceId: victimWs, kind: "channel", name: `self-${run}`, createdBySub: sub("vowner"), memberSubs: [sub("vowner"), sub("alice")] });
    const seats = (await db().select().from(channelMembers).where(eq(channelMembers.channelId, ch.id))).map((x) => x.sub).sort();
    expect(seats).toEqual([sub("alice"), sub("vowner")].sort());
  });

  it("acceptInvite: existing active member keeps role; offboarded member is reactivated; a forged foreign scope is never seated", async () => {
    const { members } = await import("@/lib/db/schema");
    const i1 = await createInvite({ workspaceId: victimWs, email: `own-${run}@example.com`, role: "Guest", invitedBySub: sub("vowner") });
    const a1 = await acceptInvite({ token: i1.token, sub: sub("vowner") });
    expect(a1).toEqual({ ok: true, workspaceId: victimWs, alreadyMember: true });
    const [owner] = await db().select().from(members).where(and(eq(members.workspaceId, victimWs), eq(members.sub, sub("vowner"))));
    expect(owner!.role).toBe("Owner");

    await addMember(victimWs, "gone", "Member");
    await db().update(members).set({ status: "offboarded" }).where(and(eq(members.workspaceId, victimWs), eq(members.sub, sub("gone"))));
    const i2 = await createInvite({ workspaceId: victimWs, email: `back-${run}@example.com`, role: "Guest", invitedBySub: sub("vowner") });
    const a2 = await acceptInvite({ token: i2.token, sub: sub("gone") });
    expect(a2).toEqual({ ok: true, workspaceId: victimWs, alreadyMember: false });
    const [g] = await db().select().from(members).where(and(eq(members.workspaceId, victimWs), eq(members.sub, sub("gone"))));
    expect([g!.status, g!.role]).toEqual(["active", "Guest"]);

    const foreign = await createChannel({ workspaceId: attackerWs, kind: "channel", name: `fs-${run}`, createdBySub: sub("mallory") });
    const token = `forged-${run}`;
    await db().insert(invites).values({ tokenHash: hashToken(token), workspaceId: victimWs, email: `f-${run}@example.com`, role: "Guest", scopeChannelId: foreign.id, invitedBySub: sub("vowner"), expiresAt: new Date(Date.now() + 3600_000) });
    expect((await acceptInvite({ token, sub: sub("forged") })).ok).toBe(true);
    expect(await db().select().from(channelMembers).where(eq(channelMembers.sub, sub("forged")))).toHaveLength(0);
    expect((await acceptInvite({ token, sub: sub("forged2") })).ok).toBe(false);
  });
});
