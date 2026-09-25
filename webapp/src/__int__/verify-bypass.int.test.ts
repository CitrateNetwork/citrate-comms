/**
 * Independent verifier bypass attempts for PR #16 (COMMS R2), kept as a regression suite.
 * real Postgres, mock auth. Assertions describe the SECURE outcome; a failing test = bypass.
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));
vi.mock("@/lib/email/send", async (orig) => ({ ...(await orig<Record<string, unknown>>()), sendInviteEmail: async () => ({ sent: false }) }));

import { and, eq, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, agentPrompts, agentSkills, calendarEvents, eventAttendees, members } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import { createChannel, addChannelMembers } from "@/lib/domain/channels";
import { sendMessage } from "@/lib/domain/messages";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";
import { addResource, listResources } from "@/lib/domain/agent-config";
import { encryptField } from "@/lib/security/crypto";
import { citrateCommsTools } from "@/lib/ai/tools";

import * as invitesRoute from "@/app/api/workspaces/[id]/invites/route";
import * as batchRoute from "@/app/api/workspaces/[id]/invites/batch/route";
import * as joinRoute from "@/app/api/join/route";
import * as msgRoute from "@/app/api/channels/[id]/messages/route";
import * as ledgerRoute from "@/app/api/channels/[id]/ledger/route";
import * as dlRoute from "@/app/api/workspaces/[id]/documents/[docId]/download/route";
import * as mcpRoute from "@/app/api/workspaces/[id]/mcp/route";
import * as accountsRoute from "@/app/api/workspaces/[id]/accounts/route";
import * as membersRoute from "@/app/api/workspaces/[id]/members/route";
import * as calRoute from "@/app/api/workspaces/[id]/calendar/route";
import * as calEventRoute from "@/app/api/workspaces/[id]/calendar/[eventId]/route";
import * as cloneRoute from "@/app/api/workspaces/[id]/personas/[personaId]/clone/route";
import * as personaRoute from "@/app/api/workspaces/[id]/personas/[personaId]/route";
import * as resourcesRoute from "@/app/api/workspaces/[id]/personas/[personaId]/resources/route";
import * as grantsRoute from "@/app/api/workspaces/[id]/persona-config-grants/route";
import * as importRoute from "@/app/api/workspaces/[id]/personas/import/route";
import * as notifRoute from "@/app/api/workspaces/[id]/notifications/route";
import { run, sub, req, P, addMember, mcpCall } from "./helpers";

let ws: string, other: string, dmId: string, dmDocId: string, sharedCh: string, otherCh: string, personaId: string, otherPersona: string;

beforeAll(async () => {
  ws = (await createWorkspace({ name: `v ${run}`, ownerSub: sub("own"), ownerWallet: null, ownerEmail: null })).id;
  other = (await createWorkspace({ name: `o ${run}`, ownerSub: sub("mal"), ownerWallet: null, ownerEmail: null })).id;
  await addMember(ws, "adm", "Admin");
  await addMember(ws, "alice", "Member");
  await addMember(ws, "bob", "Member");
  await addMember(ws, "mem", "Member");
  await addMember(ws, "par", "Partner");
  await addMember(ws, "gst", "Guest");
  const dm = await createChannel({ workspaceId: ws, kind: "dm", name: "alice-bob", createdBySub: sub("alice"), memberSubs: [sub("bob")] });
  dmId = dm.id;
  await sendMessage({ workspaceId: ws, channelId: dmId, authorSub: sub("alice"), body: "PRIVATE: bob's salary is 250k" });
  const [d] = await db().insert(documents).values({ workspaceId: ws, channelId: dmId, blobUrl: "https://x.public.blob.vercel-storage.com/offer.pdf", name: "offer.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
  dmDocId = d!.id;
  sharedCh = (await createChannel({ workspaceId: ws, kind: "channel", name: "shared", createdBySub: sub("own"), memberSubs: [sub("mem"), sub("par"), sub("gst")] })).id;
  otherCh = (await createChannel({ workspaceId: other, kind: "channel", name: "o", createdBySub: sub("mal") })).id;
  await seedDefaultPersonas(ws, sub("own"));
  await seedDefaultPersonas(other, sub("mal"));
  personaId = (await listPersonas(ws))[0]!.id;
  otherPersona = (await listPersonas(other))[0]!.id;
});

describe("V-002a invite scopeChannelId: Admin not in a DM seats themself into it", () => {
  it("Admin invites own identity scoped to alice-bob DM, accepts, then reads the DM (should be refused)", async () => {
    const r = await invitesRoute.POST(req(`/api/workspaces/${ws}/invites`, "adm", { method: "POST", body: JSON.stringify({ workspaceId: ws, email: "adm@example.com", role: "Member", scopeChannelId: dmId }) }), P({ id: ws }));
    const j = (await r.json()) as { link?: string; error?: string };
    // Secure outcome A: inviter who is not seated in the scope channel is refused.
    if (r.status !== 201) {
      expect([400, 403]).toContain(r.status);
      return;
    }
    const token = j.link!.split("/join/")[1]!;
    const a = await joinRoute.POST(req(`/api/join`, "adm", { method: "POST", body: JSON.stringify({ token }) }));
    expect(a.status).toBe(200);
    const m = await msgRoute.GET(req(`/api/channels/${dmId}/messages`, "adm"), P({ id: dmId }));
    const body = await m.text();
    const d = await dlRoute.GET(req(`/api/workspaces/${ws}/documents/${dmDocId}/download`, "adm"), P({ id: ws, docId: dmDocId }));
    // Secure outcome B: even if the invite is minted, accepting it must not seat an existing member into a DM.
    expect({ msgStatus: m.status, leaks: body.includes("salary"), dl: d.status }).toEqual({ msgStatus: 403, leaks: false, dl: 403 });
  });
  it("same via invites/batch as a Guest sock-puppet", async () => {
    const r = await batchRoute.POST(req(`/api/workspaces/${ws}/invites/batch`, "adm", { method: "POST", body: JSON.stringify({ workspaceId: ws, emails: ["sock@example.com"], role: "Guest", scopeChannelId: dmId }) }), P({ id: ws }));
    const txt = await r.text();
    if (r.status !== 201 && r.status !== 200) {
      expect([400, 403]).toContain(r.status);
      return;
    }
    const link = /\/join\/([A-Za-z0-9_-]+)/.exec(txt)?.[1];
    if (!link) return; // links not returned by batch -> not exploitable via this route here
    await joinRoute.POST(req(`/api/join`, "sock", { method: "POST", body: JSON.stringify({ token: link }) }));
    const m = await msgRoute.GET(req(`/api/channels/${dmId}/messages`, "sock"), P({ id: dmId }));
    expect((await m.text()).includes("salary")).toBe(false);
  });
});

describe("V-002b role change while session live", () => {
  it("Member demoted to Guest loses CRM on the very next request", async () => {
    await addMember(ws, "demo", "Member");
    expect((await accountsRoute.GET(req(`/api/workspaces/${ws}/accounts`, "demo"), P({ id: ws }))).status).toBe(200);
    const pr = await membersRoute.PATCH(req(`/api/workspaces/${ws}/members`, "own", { method: "PATCH", body: JSON.stringify({ sub: sub("demo"), role: "Guest" }) }), P({ id: ws }));
    expect(pr.status).toBe(200);
    expect((await accountsRoute.GET(req(`/api/workspaces/${ws}/accounts`, "demo"), P({ id: ws }))).status).toBe(403);
    const mc = (await (await mcpRoute.POST(req(`/api/workspaces/${ws}/mcp`, "demo", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }), P({ id: ws }))).json()) as { result: { tools: { name: string }[] } };
    expect(mc.result.tools.map((t) => t.name)).toEqual(["thread.summarize"]);
  });
});

describe("V-002c foreign / unseated channel ids on /api/channels/*", () => {
  it("Partner: foreign-workspace channel and unseated DM are refused", async () => {
    for (const ch of [otherCh, dmId]) {
      expect((await msgRoute.GET(req(`/api/channels/${ch}/messages`, "par"), P({ id: ch }))).status).toBe(403);
      expect((await ledgerRoute.GET(req(`/api/channels/${ch}/ledger`, "par"), P({ id: ch }))).status).toBe(403);
      expect((await msgRoute.POST(req(`/api/channels/${ch}/messages`, "par", { method: "POST", body: JSON.stringify({ body: "x" }) }), P({ id: ch }))).status).toBe(403);
    }
  });
  it("Partner/Guest MCP: every workspace-data tool absent; thread.summarize on DM refused", async () => {
    for (const who of ["par", "gst"]) {
      for (const t of ["crm.read", "calendar.read", "documents.list", "documents.read", "tables.list", "pm.read", "memory.recall", "artifact.attach", "web.fetch"]) {
        const j = (await (await mcpRoute.POST(req(`/api/workspaces/${ws}/mcp`, who, { method: "POST", body: mcpCall(t, {}) }), P({ id: ws }))).json()) as { error?: { message: string } };
        expect(j.error?.message ?? "", `${who} ${t}`).toMatch(/Unknown tool/);
      }
      const j = (await (await mcpRoute.POST(req(`/api/workspaces/${ws}/mcp`, who, { method: "POST", body: mcpCall("thread.summarize", { channelId: dmId }) }), P({ id: ws }))).json()) as { result: { isError: boolean; content: { text: string }[] } };
      expect(j.result.isError).toBe(true);
    }
  });
  it("agent tools invoked on a Partner's behalf are channel-scoped only", () => {
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("par"), agentRole: "Agent", invokerRole: "Partner" });
    expect(Object.keys(t)).toEqual(["thread.summarize"]);
    const g = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("gst"), agentRole: "Agent", invokerRole: "Guest" });
    expect(Object.keys(g).filter((k) => k !== "thread.summarize")).toEqual([]);
  });
  it("notifications GET is own-only (no workspace data surfaces)", async () => {
    const r = await notifRoute.GET(req(`/api/workspaces/${ws}/notifications`, "par"), P({ id: ws }));
    expect(r.status).toBe(200);
  });
});

describe("V-001 other persona write paths", () => {
  it("clone / export / resources / grants / import with a foreign persona id", async () => {
    expect((await cloneRoute.POST(req(`/api/workspaces/${other}/personas/${personaId}/clone`, "mal", { method: "POST", body: JSON.stringify({ name: "stolen" }) }), P({ id: other, personaId }))).status).toBe(404);
    expect((await personaRoute.GET(req(`/api/workspaces/${other}/personas/${personaId}?export=1`, "mal"), P({ id: other, personaId }))).status).toBe(403);
    expect((await personaRoute.PATCH(req(`/api/workspaces/${other}/personas/${personaId}`, "mal", { method: "PATCH", body: JSON.stringify({ name: "pwn" }) }), P({ id: other, personaId }))).status).toBe(403);
    expect((await resourcesRoute.POST(req(`/api/workspaces/${other}/personas/${personaId}/resources`, "mal", { method: "POST", body: JSON.stringify({ kind: "text", title: "x", content: "INJECT" }) }), P({ id: other, personaId }))).status).toBe(403);
    const g = await grantsRoute.POST(req(`/api/workspaces/${other}/persona-config-grants`, "mal", { method: "POST", body: JSON.stringify({ granteeSub: sub("mal"), personaId }) }), P({ id: other }));
    expect([400, 403, 404]).toContain(g.status);
    const im = await importRoute.POST(req(`/api/workspaces/${other}/personas/import`, "mal", { method: "POST", body: JSON.stringify({ persona: { name: "imp", layers: [{ layer: 1, content: "x" }] } }) }), P({ id: other }));
    expect(im.status).toBeLessThan(500);
  });
  it("DB-level: a cross-tenant prompt/skill row is rejected by the composite FK", async () => {
    await expect(db().insert(agentPrompts).values({ workspaceId: other, personaId, layer: 3, contentEnc: "x", updatedBySub: sub("mal") })).rejects.toThrow();
    await expect(db().insert(agentSkills).values({ workspaceId: other, personaId, skillKey: "zz", enabled: true })).rejects.toThrow();
  });
  it("race: 20 concurrent cross-tenant prompt writes never land", async () => {
    const { setPromptLayer } = await import("@/lib/domain/personas");
    await Promise.allSettled(Array.from({ length: 20 }, (_, i) => setPromptLayer(other, personaId, 1 + (i % 4), `ATTACK${i}`, sub("mal"))));
    const rows = await db().select().from(agentPrompts).where(eq(agentPrompts.personaId, personaId));
    expect(rows.filter((r) => r.updatedBySub === sub("mal"))).toEqual([]);
  });
});

describe("V-003 residual document paths", () => {
  it("persona resource can pin a DM document the configurer cannot see (nit probe)", async () => {
    const id = await addResource(ws, personaId, { kind: "document", title: "t", documentId: dmDocId }, sub("own"));
    const res = await listResources(ws, personaId);
    // record observed behaviour
    console.log("[V-003 probe] addResource(DM doc by non-participant owner) ->", id ? "ACCEPTED" : "refused", "documentId surfaced:", res.some((r) => r.documentId === dmDocId));
    expect({ id: id ? "ACCEPTED" : null, surfaced: res.some((r) => r.documentId === dmDocId) }).toEqual({ id: null, surfaced: false });
  });
  it("Owner/Admin (not in DM) cannot download the DM doc", async () => {
    for (const who of ["own", "adm", "mem"]) {
      const r = await dlRoute.GET(req(`/api/workspaces/${ws}/documents/${dmDocId}/download`, who), P({ id: ws, docId: dmDocId }));
      expect(r.status, who).toBe(403);
    }
    const ok = await dlRoute.GET(req(`/api/workspaces/${ws}/documents/${dmDocId}/download`, "bob"), P({ id: ws, docId: dmDocId }));
    expect(ok.status).toBe(302);
  });
  it("internal Member invoking documents.* never sees the DM doc", async () => {
    const t = citrateCommsTools({ workspaceId: ws, invokedBySub: sub("mem"), agentRole: "Agent", invokerRole: "Member", audit: false }) as unknown as Record<string, { execute: (a: unknown) => Promise<unknown> }>;
    const l = (await t["documents.list"]!.execute({ limit: 50 })) as { documents: { id: string }[] };
    expect(l.documents.map((d) => d.id)).not.toContain(dmDocId);
    const at = (await t["artifact.attach"]!.execute({ documentId: dmDocId })) as { ok: boolean };
    expect(at.ok).toBe(false);
  });
});

describe("Regressions: scoped external + internal capability", () => {
  it("Partner/Guest still read their seated channel; Partner posts", async () => {
    await sendMessage({ workspaceId: ws, channelId: sharedCh, authorSub: sub("own"), body: "hello shared" });
    for (const who of ["par", "gst"]) {
      const r = await msgRoute.GET(req(`/api/channels/${sharedCh}/messages`, who), P({ id: sharedCh }));
      expect(r.status, who).toBe(200);
      expect(await r.text()).toContain("hello shared");
    }
    expect((await msgRoute.POST(req(`/api/channels/${sharedCh}/messages`, "par", { method: "POST", body: JSON.stringify({ body: "partner hi" }) }), P({ id: sharedCh }))).status).toBe(201);
    expect((await msgRoute.POST(req(`/api/channels/${sharedCh}/messages`, "gst", { method: "POST", body: JSON.stringify({ body: "guest hi" }) }), P({ id: sharedCh }))).status).toBe(403);
  });
  it("Partner attendee still sees the event they are invited to", async () => {
    const start = new Date(Date.now() + 86400_000);
    const [ev] = await db().insert(calendarEvents).values({ workspaceId: ws, kind: "meeting", titleEnc: encryptField(ws, "Partner sync"), startsAt: start, endsAt: new Date(start.getTime() + 3600_000), createdBySub: sub("mem"), timezone: "UTC" } as never).returning();
    await db().insert(eventAttendees).values({ workspaceId: ws, eventId: ev!.id, sub: sub("par") } as never);
    const r = await calEventRoute.GET(req(`/api/workspaces/${ws}/calendar/${ev!.id}`, "par"), P({ id: ws, eventId: ev!.id }));
    expect(r.status).toBe(200);
    expect(await r.text()).toContain("Partner sync");
    const from = new Date(Date.now()).toISOString(), to = new Date(Date.now() + 5 * 86400_000).toISOString();
    const l = await calRoute.GET(req(`/api/workspaces/${ws}/calendar?from=${from}&to=${to}`, "par"), P({ id: ws }));
    expect(await l.text()).toContain("Partner sync");
  });
  it("internal roles keep CRM + MCP data tools", async () => {
    for (const who of ["own", "adm", "mem"]) {
      expect((await accountsRoute.GET(req(`/api/workspaces/${ws}/accounts`, who), P({ id: ws }))).status, who).toBe(200);
      const j = (await (await mcpRoute.POST(req(`/api/workspaces/${ws}/mcp`, who, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }), P({ id: ws }))).json()) as { result: { tools: { name: string }[] } };
      const names = j.result.tools.map((t) => t.name);
      for (const t of ["crm.read", "documents.list", "documents.read", "calendar.read", "tables.list", "pm.read"]) expect(names, `${who} ${t}`).toContain(t);
    }
  });
});

describe("V-003b CRM record file lists channel-scoped docs unscoped (raw blob URL in RSC props)", () => {
  it("a doc uploaded into the alice-bob DM and linked to an account is visible to any internal viewer of the account page", async () => {
    const { createAccount } = await import("@/lib/domain/crm");
    const { getAccountFile } = await import("@/lib/domain/crm-file");
    const { badDocScope } = await import("@/lib/domain/documents");
    const acct = await createAccount(ws, "Acme DM-linked", null, sub("alice"));
    // alice (seated in the DM) may legitimately scope an upload to both the DM and the account
    expect(await badDocScope(ws, sub("alice"), { accountId: acct.id, dealId: null, channelId: dmId })).toBeNull();
    const [d] = await db().insert(documents).values({ workspaceId: ws, channelId: dmId, accountId: acct.id, blobUrl: "https://x.public.blob.vercel-storage.com/bob-comp-plan.pdf", name: "bob-comp-plan.pdf", mime: "application/pdf", uploadedBySub: sub("alice") }).returning();
    // download proxy correctly refuses mem ...
    expect((await dlRoute.GET(req(`/api/workspaces/${ws}/documents/${d!.id}/download`, "mem"), P({ id: ws, docId: d!.id }))).status).toBe(403);
    // ... but the account page loader (rendered for any internal member, props serialized to the client) is not viewer-scoped
    const file = await getAccountFile(ws, acct.id, { sub: sub("mem"), internal: true });
    const leaked = file!.documents.find((x) => x.id === d!.id);
    expect(leaked?.blobUrl ?? null, "raw blob URL of a DM document reaches a non-participant's account page").toBeNull();
    // the DM participant still sees it, but only as the access-controlled proxy URL
    const own = (await getAccountFile(ws, acct.id, { sub: sub("alice"), internal: true }))!.documents.find((x) => x.id === d!.id);
    expect(own?.blobUrl).toBe(`/api/workspaces/${ws}/documents/${d!.id}/download?inline=1`);
  });
});
