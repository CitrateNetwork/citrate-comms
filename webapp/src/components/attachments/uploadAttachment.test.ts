/**
 * Client upload helper: files go to the PRIVATE store under the workspace's `comms/<id>/`
 * prefix (the token issuer and finalize both enforce that prefix). Pins the literal
 * arguments passed to `upload()`.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const upload = vi.fn<(...a: unknown[]) => unknown>();
vi.mock("@vercel/blob/client", () => ({ upload: (...a: unknown[]) => upload(...a) }));

import { uploadAttachment } from "./uploadAttachment";

const WS = "11111111-1111-1111-1111-111111111111";
const realFetch = globalThis.fetch;

beforeEach(() => {
  upload.mockReset();
  upload.mockResolvedValue({ url: `https://privstore.private.blob.vercel-storage.com/comms/${WS}/brief-xyz.pdf` });
  globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ document: { id: "doc-1", name: "brief.pdf" } }), { status: 201 })) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("uploadAttachment", () => {
  it("uploads privately under comms/<workspaceId>/ and finalizes the returned URL", async () => {
    const r = await uploadAttachment(WS, { channelId: "c1" }, new File(["x"], "brief.pdf", { type: "application/pdf" }));
    expect(r.ok).toBe(true);
    const [pathname, , opts] = upload.mock.calls[0] as [string, unknown, { access: string; handleUploadUrl: string }];
    expect(pathname).toBe(`comms/${WS}/brief.pdf`);
    expect(opts.access).toBe("private");
    expect(opts.handleUploadUrl).toBe(`/api/workspaces/${WS}/documents/upload-token`);
    const [url, init] = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`/api/workspaces/${WS}/documents/finalize`);
    expect(JSON.parse(String(init.body))).toMatchObject({ blobUrl: `https://privstore.private.blob.vercel-storage.com/comms/${WS}/brief-xyz.pdf` });
  });
});
