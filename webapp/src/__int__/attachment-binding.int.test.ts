/**
 * Attachment object binding: an object is bound to the workspace whose `comms/<id>/` prefix it
 * lives under. Real route handlers + Postgres; only the Blob network primitives are stubbed.
 * Covers traversal forms, prefix/case collisions, host variants, finalize races, re-finalizing
 * another workspace's object, and the legacy (pre-migration) streaming path.
 */
import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";

vi.mock("@/lib/security/ratelimit", () => ({
  limit: async () => ({ success: true, remaining: 99 }),
  rateLimitConfigured: () => true,
}));

const signedFor: string[] = [];
const readFor: string[] = [];
vi.mock("@vercel/blob", async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return {
    ...actual,
    issueSignedToken: async (o: { pathname: string; validUntil: number }) => {
      signedFor.push(o.pathname);
      return { clientSigningToken: "c", delegationToken: "d", validUntil: o.validUntil };
    },
    presignUrl: async (_t: unknown, o: { pathname: string; validUntil: number }) => ({
      presignedUrl: `https://privstore.private.blob.vercel-storage.com/${o.pathname}?vercel-blob-signature=SIG&vercel-blob-valid-until=${o.validUntil}`,
    }),
    get: async (pathname: string) => {
      readFor.push(pathname);
      const body = new TextEncoder().encode("VICTIM CONFIDENTIAL CONTRACT TERMS");
      return {
        statusCode: 200,
        blob: { size: body.byteLength, contentType: "text/plain" },
        stream: new ReadableStream({ start(c) { c.enqueue(body); c.close(); } }),
      };
    },
  };
});

import { eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents } from "@/lib/db/schema";
import { createWorkspace } from "@/lib/domain/workspaces";
import * as finalizeRoute from "@/app/api/workspaces/[id]/documents/finalize/route";
import * as dlRoute from "@/app/api/workspaces/[id]/documents/[docId]/download/route";
import { run, sub, req, P } from "./helpers";

const PRIV = "https://privstore.private.blob.vercel-storage.com";
const PUB = "https://pubstore.public.blob.vercel-storage.com";
let wsV: string, wsA: string;

const fin = (ws: string, who: string, blobUrl: string, name = "contract.txt", mime = "text/plain") =>
  finalizeRoute.POST(req(`/api/workspaces/${ws}/documents/finalize`, who, { method: "POST", body: JSON.stringify({ blobUrl, name, mime }) }), P({ id: ws }));

beforeAll(async () => {
  wsV = (await createWorkspace({ name: `bvictim ${run}`, ownerSub: sub("bvictim"), ownerWallet: null, ownerEmail: null })).id;
  wsA = (await createWorkspace({ name: `battacker ${run}`, ownerSub: sub("bmallory"), ownerWallet: null, ownerEmail: null })).id;
});
beforeEach(() => { signedFor.length = 0; readFor.length = 0; });

describe("cross-workspace registration", () => {
  it("attacker can no longer register the victim's private object", async () => {
    const r = await fin(wsA, "bmallory", `${PRIV}/comms/${wsV}/contract-AbCdEf0123456789.txt`);
    expect(r.status).toBe(400);
    expect(readFor).toEqual([]);
    expect(signedFor).toEqual([]);
  });
});

describe("path traversal against the comms/<ws>/ prefix", () => {
  const variants = () => [
    ["dotdot", `${PRIV}/comms/${wsA}/../${wsV}/contract.txt`],
    ["encoded dot", `${PRIV}/comms/${wsA}/%2e%2e/${wsV}/contract.txt`],
    ["mixed encoded dot", `${PRIV}/comms/${wsA}/.%2E/${wsV}/contract.txt`],
    ["backslash", `${PRIV}/comms/${wsA}/..\\${wsV}\\contract.txt`],
    ["double slash dotdot", `${PRIV}/comms/${wsA}//../../comms/${wsV}/contract.txt`],
    ["leading double slash", `${PRIV}//comms/${wsV}/contract.txt`],
    ["encoded prefix", `${PRIV}/comms%2f${wsA}%2f..%2f${wsV}/contract.txt`],
  ] as const;
  it("normalizing forms are rejected (bad_scope) and nothing is read/signed", async () => {
    for (const [label, u] of variants()) {
      const r = await fin(wsA, "bmallory", u);
      expect(r.status, label).toBe(400);
    }
    expect(readFor).toEqual([]);
    expect(signedFor).toEqual([]);
  });
});

describe("prefix collision + case", () => {
  it("upper-cased victim id and victim id with a suffix are rejected", async () => {
    expect((await fin(wsA, "bmallory", `${PRIV}/comms/${wsV.toUpperCase()}/contract.txt`)).status).toBe(400);
    expect((await fin(wsA, "bmallory", `${PRIV}/comms/${wsA}x/contract.txt`)).status).toBe(400);
    expect((await fin(wsA, "bmallory", `${PRIV}/comms/${wsA.slice(0, -1)}/contract.txt`)).status).toBe(400);
    expect((await fin(wsA, "bmallory", `${PRIV}/Comms/${wsA}/contract.txt`)).status).toBe(400);
    expect((await fin(wsA, "bmallory", `${PRIV}/comms/${wsA}`)).status).toBe(400); // no trailing slash
  });
  it("attacker addressing their own workspace with an upper-cased id cannot reach the victim", async () => {
    const r = await fin(wsA.toUpperCase(), "bmallory", `${PRIV}/comms/${wsV}/contract.txt`);
    expect([400, 403, 404]).toContain(r.status);
    expect(signedFor).toEqual([]);
  });
});

describe("host variations", () => {
  it("legacy host, foreign host, trailing dot, userinfo, http, odd port are bad_host; case/query/fragment on victim path are bad_scope", async () => {
    const vPath = `comms/${wsV}/contract.txt`;
    for (const u of [
      `${PUB}/${vPath}`,
      `https://privstore.public.blob.vercel-storage.com/${vPath}`,
      `https://pubstore.private.blob.vercel-storage.com/${vPath}`,
      `https://privstore.private.blob.vercel-storage.com./${vPath}`,
      `https://x@privstore.private.blob.vercel-storage.com/${vPath}`,
      `http://privstore.private.blob.vercel-storage.com/${vPath}`,
      `https://privstore.private.blob.vercel-storage.com:8443/${vPath}`,
      `https://evil.example/${PRIV}/${vPath}`,
    ]) {
      const r = await fin(wsA, "bmallory", u);
      expect(r.status, u).toBe(400);
      expect(await r.json(), u).toMatchObject({ error: "bad_host" });
    }
    for (const u of [
      `https://PRIVSTORE.PRIVATE.BLOB.VERCEL-STORAGE.COM/${vPath}`,
      `${PRIV}/${vPath}?x=1`,
      `${PRIV}/${vPath}#frag`,
      `${PRIV}:443/${vPath}`,
      `${PRIV}/${vPath}?/comms/${wsA}/`,
      `${PRIV}/${vPath}#/comms/${wsA}/`,
    ]) {
      const r = await fin(wsA, "bmallory", u);
      expect(r.status, u).toBe(400);
    }
    expect(readFor).toEqual([]);
  });
  it("query/fragment decoys cannot smuggle the victim path into the signed pathname", async () => {
    const r = await fin(wsA, "bmallory", `${PRIV}/comms/${wsA}/x.png?p=/comms/${wsV}/contract.txt#comms/${wsV}/y`, "x.png", "image/png");
    expect(r.status).toBe(201);
    const docId = ((await r.json()) as { document: { id: string } }).document.id;
    const dl = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${docId}/download`, "bmallory"), P({ id: wsA, docId }));
    expect(dl.status).toBe(302);
    expect(signedFor).toEqual([`comms/${wsA}/x.png`]);
  });
});

describe("races + re-finalize", () => {
  it("victim and attacker race to finalize the victim's fresh object: only the victim wins", async () => {
    const u = `${PRIV}/comms/${wsV}/race-${run}.txt`;
    const rs = await Promise.all([fin(wsV, "bvictim", u), fin(wsA, "bmallory", u), fin(wsA, "bmallory", u), fin(wsV, "bvictim", u)]);
    expect(rs.map((r) => r.status)).toEqual([201, 400, 400, 201]);
    const rows = await db().select({ ws: documents.workspaceId }).from(documents).where(eq(documents.blobUrl, u));
    expect(rows.every((r) => r.ws === wsV)).toBe(true);
  });
  it("re-finalizing another workspace's already-finalized object (and URL variants) fails", async () => {
    const u = `${PRIV}/comms/${wsV}/final-${run}.txt`;
    expect((await fin(wsV, "bvictim", u)).status).toBe(201);
    for (const v of [u, `${u}?a`, `${u}#b`, u.replace("privstore", "PRIVSTORE"), u.replace(".com/", ".com:443/")]) {
      expect((await fin(wsA, "bmallory", v)).status, v).toBe(400);
    }
  });
  it("migrated (unprefixed) and legacy objects cannot be claimed", async () => {
    expect((await fin(wsA, "bmallory", `${PRIV}/comms/migrated/0b8e6c1e-8a3e-4b0e-9d7e-3f1c2a4b5c6d.txt`)).status).toBe(400);
    expect((await fin(wsA, "bmallory", `${PUB}/comms/${wsV}/legacy-AbC.txt`)).status).toBe(400);
    expect((await fin(wsA, "bmallory", `${PUB}/legacy-unprefixed-AbC.txt`)).status).toBe(400);
  });
});

describe("legacy objects are streamed, never redirected to the raw public URL", () => {
  it("legacy row: 200 streamed bytes, no Location; after the legacy store is retired: 404 (no redirect)", async () => {
    const legacyUrl = `${PUB}/old-contract-XyZ.txt`;
    const [d] = await db().insert(documents).values({ workspaceId: wsV, blobUrl: legacyUrl, name: "old.txt", mime: "text/plain", uploadedBySub: sub("bvictim") }).returning();
    const realFetch = globalThis.fetch;
    const fetched: string[] = [];
    globalThis.fetch = (async (u: string | URL | Request) => {
      fetched.push(String(u));
      return new Response("LEGACY BYTES", { status: 200, headers: { "content-type": "text/plain", "content-length": "12" } });
    }) as typeof fetch;
    try {
      const r = await dlRoute.GET(req(`/api/workspaces/${wsV}/documents/${d!.id}/download`, "bvictim"), P({ id: wsV, docId: d!.id }));
      expect(r.status).toBe(200);
      expect(r.headers.get("location")).toBeNull();
      expect(r.headers.get("content-disposition")).toContain("attachment");
      expect(r.headers.get("cache-control")).toBe("private, no-store");
      expect(await r.text()).toBe("LEGACY BYTES");
      expect(fetched).toEqual([legacyUrl]);
      // attacker in their own workspace cannot reach the victim's legacy doc
      const x = await dlRoute.GET(req(`/api/workspaces/${wsA}/documents/${d!.id}/download`, "bmallory"), P({ id: wsA, docId: d!.id }));
      expect(x.status).toBe(404);
      const prev = process.env.BLOB_LEGACY_READ_WRITE_TOKEN;
      delete process.env.BLOB_LEGACY_READ_WRITE_TOKEN;
      try {
        const gone = await dlRoute.GET(req(`/api/workspaces/${wsV}/documents/${d!.id}/download`, "bvictim"), P({ id: wsV, docId: d!.id }));
        expect(gone.status).toBe(404);
        expect(gone.headers.get("location")).toBeNull();
      } finally {
        process.env.BLOB_LEGACY_READ_WRITE_TOKEN = prev;
      }
    } finally {
      globalThis.fetch = realFetch;
    }
  });
  it("a row on a foreign host is 404, never redirected", async () => {
    const [d] = await db().insert(documents).values({ workspaceId: wsV, blobUrl: "https://evil9.public.blob.vercel-storage.com/x.txt", name: "x.txt", mime: "text/plain", uploadedBySub: sub("bvictim") }).returning();
    const r = await dlRoute.GET(req(`/api/workspaces/${wsV}/documents/${d!.id}/download`, "bvictim"), P({ id: wsV, docId: d!.id }));
    expect(r.status).toBe(404);
    expect(r.headers.get("location")).toBeNull();
  });
});
