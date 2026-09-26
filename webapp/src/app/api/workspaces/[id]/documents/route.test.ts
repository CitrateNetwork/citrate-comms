/**
 * Server upload route: the original is written to the PRIVATE store, under the uploading
 * workspace's `comms/<id>/` prefix. Pins the literal arguments passed to `put()` so neither a
 * flipped access value nor a dropped prefix at this call site can regress silently.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const put = vi.fn<(...a: unknown[]) => unknown>();
const requireCapability = vi.fn<(...a: unknown[]) => unknown>();
const ingestDocument = vi.fn<(...a: unknown[]) => unknown>();
const badDocScope = vi.fn<(...a: unknown[]) => unknown>();

vi.mock("@vercel/blob", () => ({ put: (...a: unknown[]) => put(...a) }));
vi.mock("@/lib/tenant/guard", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  requireCapability: (...a: unknown[]) => requireCapability(...a),
}));
vi.mock("@/lib/domain/documents", () => ({
  ingestDocument: (...a: unknown[]) => ingestDocument(...a),
  badDocScope: (...a: unknown[]) => badDocScope(...a),
}));

import { POST } from "./route";

const WS = "11111111-1111-1111-1111-111111111111";

function upload(name: string) {
  const form = new FormData();
  form.set("file", new File(["hello"], name, { type: "text/plain" }));
  return POST(new Request(`http://localhost/api/workspaces/${WS}/documents`, { method: "POST", body: form }), {
    params: Promise.resolve({ id: WS }),
  });
}

beforeEach(() => {
  for (const m of [put, requireCapability, ingestDocument, badDocScope]) m.mockReset();
  process.env.BLOB_READ_WRITE_TOKEN = ["vercel_blob_rw", "privstore", "fixture"].join("_");
  requireCapability.mockResolvedValue({ sub: "alice", role: "Member" });
  badDocScope.mockResolvedValue(null);
  ingestDocument.mockResolvedValue({ id: "doc-1", chunks: 1 });
  put.mockResolvedValue({ url: `https://privstore.private.blob.vercel-storage.com/comms/${WS}/notes-abc.txt` });
});

describe("server upload writes to the private store under the workspace prefix", () => {
  it("calls put() with access 'private' and a comms/<workspaceId>/ pathname", async () => {
    const res = await upload("notes.txt");
    expect(res.status).toBe(201);
    expect(put).toHaveBeenCalledTimes(1);
    const [pathname, , opts] = put.mock.calls[0] as [string, unknown, { access: string; addRandomSuffix: boolean }];
    expect(pathname).toBe(`comms/${WS}/notes.txt`);
    expect(opts.access).toBe("private");
    expect(opts.addRandomSuffix).toBe(true);
    expect(ingestDocument).toHaveBeenCalledWith(expect.objectContaining({ workspaceId: WS, blobUrl: `https://privstore.private.blob.vercel-storage.com/comms/${WS}/notes-abc.txt` }));
  });

  it("stores text only (no blob URL) when the private put is refused", async () => {
    put.mockRejectedValue(new Error("store refused"));
    const res = await upload("notes.txt");
    expect(res.status).toBe(201);
    expect(ingestDocument).toHaveBeenCalledWith(expect.objectContaining({ blobUrl: "" }));
  });
});
