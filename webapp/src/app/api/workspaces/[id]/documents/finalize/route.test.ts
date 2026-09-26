/**
 * Finalize object-binding (ATT-HARDEN). A caller may only finalize an object that is on this
 * deployment's PRIVATE store, under their own workspace's prefix, and not already bound to
 * another workspace — so one workspace can't register (and then read/sign) another's object.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Private store host: privstore.private.blob.vercel-storage.com
process.env.BLOB_READ_WRITE_TOKEN = ["vercel_blob_rw", "privstore", "fixture"].join("_");

const requireCapability = vi.fn<(...a: unknown[]) => unknown>();
const ingestDocument = vi.fn<(...a: unknown[]) => unknown>();
const badDocScope = vi.fn<(...a: unknown[]) => unknown>();
const blobUrlBoundToOtherWorkspace = vi.fn<(...a: unknown[]) => unknown>();
const readBlobBytes = vi.fn<(...a: unknown[]) => unknown>();

vi.mock("@/lib/tenant/guard", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  requireCapability: (...a: unknown[]) => requireCapability(...a),
}));
vi.mock("@/lib/domain/documents", () => ({
  ingestDocument: (...a: unknown[]) => ingestDocument(...a),
  badDocScope: (...a: unknown[]) => badDocScope(...a),
  blobUrlBoundToOtherWorkspace: (...a: unknown[]) => blobUrlBoundToOtherWorkspace(...a),
}));
vi.mock("@/lib/domain/import-store", () => ({ ingestTable: vi.fn() }));
vi.mock("@/lib/domain/import-parse", () => ({ isTabularFile: () => false, summarizeParsed: () => "", parseWorkbook: vi.fn() }));
// Keep blobPathname real; only stub the network read.
vi.mock("@/lib/security/blob-signing", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  readBlobBytes: (...a: unknown[]) => readBlobBytes(...a),
}));

import { POST } from "./route";

const WS = "11111111-1111-1111-1111-111111111111";
const OTHER_WS = "22222222-2222-2222-2222-222222222222";
const PRIV = "https://privstore.private.blob.vercel-storage.com";

function post(body: Record<string, unknown>) {
  return POST(
    new Request(`http://localhost/api/workspaces/${WS}/documents/finalize`, { method: "POST", body: JSON.stringify(body) }),
    { params: Promise.resolve({ id: WS }) },
  );
}

beforeEach(() => {
  for (const m of [requireCapability, ingestDocument, badDocScope, blobUrlBoundToOtherWorkspace, readBlobBytes]) m.mockReset();
  requireCapability.mockResolvedValue({ sub: "alice", role: "Member" });
  badDocScope.mockResolvedValue(null);
  blobUrlBoundToOtherWorkspace.mockResolvedValue(false);
  ingestDocument.mockResolvedValue({ id: "doc-1", chunks: 0 });
  readBlobBytes.mockResolvedValue(null);
});

describe("finalize refuses objects not bound to the caller's workspace", () => {
  it("rejects a URL on another store (bad_host)", async () => {
    const res = await post({ blobUrl: `https://attacker9.private.blob.vercel-storage.com/comms/${WS}/x.png`, name: "x.png", mime: "image/png" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "bad_host" });
    expect(ingestDocument).not.toHaveBeenCalled();
  });

  it("rejects a legacy PUBLIC object — new uploads must be private (bad_host)", async () => {
    const res = await post({ blobUrl: `https://privstore.public.blob.vercel-storage.com/comms/${WS}/x.png`, name: "x.png", mime: "image/png" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "bad_host" });
    expect(ingestDocument).not.toHaveBeenCalled();
  });

  it("rejects a private object under ANOTHER workspace's prefix (bad_scope)", async () => {
    const res = await post({ blobUrl: `${PRIV}/comms/${OTHER_WS}/victim.png`, name: "victim.png", mime: "image/png" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "bad_scope" });
    expect(ingestDocument).not.toHaveBeenCalled();
  });

  it("rejects an object already bound to another workspace's document (bad_scope)", async () => {
    blobUrlBoundToOtherWorkspace.mockResolvedValue(true);
    const res = await post({ blobUrl: `${PRIV}/comms/${WS}/legacy-collision.png`, name: "x.png", mime: "image/png" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "bad_scope" });
    expect(blobUrlBoundToOtherWorkspace).toHaveBeenCalledWith(WS, `${PRIV}/comms/${WS}/legacy-collision.png`);
    expect(ingestDocument).not.toHaveBeenCalled();
  });

  it("accepts a private object under the caller's own prefix (201)", async () => {
    const res = await post({ blobUrl: `${PRIV}/comms/${WS}/mine.png`, name: "mine.png", mime: "image/png" });
    expect(res.status).toBe(201);
    expect(ingestDocument).toHaveBeenCalledWith(expect.objectContaining({ workspaceId: WS, blobUrl: `${PRIV}/comms/${WS}/mine.png` }));
  });
});
