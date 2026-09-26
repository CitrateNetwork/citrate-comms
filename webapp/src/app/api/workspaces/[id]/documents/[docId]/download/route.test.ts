/**
 * Download proxy hardening (ATT-HARDEN). The proxy must authorize the viewer per document
 * BEFORE any URL is issued, and then hand back only a short-lived signed URL — never the
 * underlying store URL.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const requireMember = vi.fn<(...a: unknown[]) => unknown>();
const getVisibleDocument = vi.fn<(...a: unknown[]) => unknown>();
const getDocument = vi.fn<(...a: unknown[]) => unknown>();
const appendAudit = vi.fn<(...a: unknown[]) => unknown>();
const signedReadUrl = vi.fn<(...a: unknown[]) => unknown>();
const streamLegacyBlobResponse = vi.fn<(...a: unknown[]) => unknown>();

vi.mock("@/lib/tenant/guard", () => ({ requireMember: (...a: unknown[]) => requireMember(...a) }));
vi.mock("@/lib/domain/documents", () => ({
  getVisibleDocument: (...a: unknown[]) => getVisibleDocument(...a),
  getDocument: (...a: unknown[]) => getDocument(...a),
}));
vi.mock("@/lib/audit/chain", () => ({ appendAudit: (...a: unknown[]) => appendAudit(...a) }));
vi.mock("@/lib/rbac/matrix", () => ({ isInternalRole: () => true }));
vi.mock("@/lib/security/blob-signing", () => ({
  signedReadUrl: (...a: unknown[]) => signedReadUrl(...a),
  streamLegacyBlobResponse: (...a: unknown[]) => streamLegacyBlobResponse(...a),
}));

import { GET } from "./route";

const WS = "11111111-1111-1111-1111-111111111111";
const DOC = "22222222-2222-2222-2222-222222222222";
const RAW = "https://store1.private.blob.vercel-storage.com/comms/w/secret.pdf";
const SIGNED = "https://store1.private.blob.vercel-storage.com/comms/w/secret.pdf?sig=ABC&validUntil=999";

function req(qs = "") {
  return new Request(`http://localhost/api/workspaces/${WS}/documents/${DOC}/download${qs}`);
}
const P = { params: Promise.resolve({ id: WS, docId: DOC }) };

beforeEach(() => {
  for (const m of [requireMember, getVisibleDocument, getDocument, appendAudit, signedReadUrl, streamLegacyBlobResponse]) m.mockReset();
  requireMember.mockResolvedValue({ sub: "alice", role: "Member" });
  appendAudit.mockResolvedValue(undefined);
  signedReadUrl.mockResolvedValue({ url: SIGNED, expiresAt: Date.now() + 120_000 });
  streamLegacyBlobResponse.mockResolvedValue(null);
});

describe("access check gates URL issuance", () => {
  it("returns 403 and issues NO signed URL when the viewer can't see the document", async () => {
    getVisibleDocument.mockResolvedValue(null);
    getDocument.mockResolvedValue({ id: DOC, blobUrl: RAW, name: "secret.pdf", mime: "application/pdf" });

    const res = await GET(req(), P);
    expect(res.status).toBe(403);
    expect(signedReadUrl).not.toHaveBeenCalled();
    expect(appendAudit).not.toHaveBeenCalled();
  });

  it("returns 404 (no URL issued) when the document does not exist", async () => {
    getVisibleDocument.mockResolvedValue(null);
    getDocument.mockResolvedValue(null);
    const res = await GET(req(), P);
    expect(res.status).toBe(404);
    expect(signedReadUrl).not.toHaveBeenCalled();
  });
});

describe("authorized reads get a signed URL, never the raw store URL", () => {
  it("download: redirects to the signed URL, audits, and issues it AFTER authorization", async () => {
    getVisibleDocument.mockResolvedValue({ id: DOC, blobUrl: RAW, name: "secret.pdf", mime: "application/pdf" });

    const res = await GET(req(), P);
    expect(res.status).toBe(302);
    const location = res.headers.get("location");
    expect(location).toBe(SIGNED);
    expect(location).not.toBe(RAW); // the raw store URL is never returned
    expect(signedReadUrl).toHaveBeenCalledWith(RAW, { download: true });
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({ event: "document_downloaded", target: DOC }));
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("inline: redirects to the signed URL and does NOT audit per impression", async () => {
    getVisibleDocument.mockResolvedValue({ id: DOC, blobUrl: RAW, name: "secret.pdf", mime: "image/png" });

    const res = await GET(req("?inline=1"), P);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(SIGNED);
    expect(signedReadUrl).toHaveBeenCalledWith(RAW, { download: false });
    expect(appendAudit).not.toHaveBeenCalled();
  });

  it("never returns the bare raw store URL on any authorized path", async () => {
    getVisibleDocument.mockResolvedValue({ id: DOC, blobUrl: RAW, name: "secret.pdf", mime: "application/pdf" });
    for (const qs of ["", "?inline=1"]) {
      const res = await GET(req(qs), P);
      const location = res.headers.get("location");
      expect(location).toBe(SIGNED); // always the signed URL
      expect(location).not.toBe(RAW); // never the unsigned store URL
      expect(new URL(location!).searchParams.get("sig")).toBe("ABC"); // carries a signature
    }
  });
});

describe("legacy objects are streamed, not redirected to a raw URL", () => {
  const LEGACY = "https://oldpub.public.blob.vercel-storage.com/legacy.pdf";

  it("streams the bytes through the proxy when there is no signed (private) URL", async () => {
    getVisibleDocument.mockResolvedValue({ id: DOC, blobUrl: LEGACY, name: "legacy.pdf", mime: "application/pdf" });
    signedReadUrl.mockResolvedValue(null); // not a private object
    streamLegacyBlobResponse.mockResolvedValue(new Response("bytes", { status: 200, headers: { "content-disposition": "attachment; filename=\"legacy.pdf\"" } }));

    const res = await GET(req(), P);
    expect(res.status).toBe(200); // streamed, not a 302 redirect
    expect(res.headers.get("location")).toBeNull();
    expect(await res.text()).toBe("bytes");
    expect(streamLegacyBlobResponse).toHaveBeenCalledWith(LEGACY, { download: true, mime: "application/pdf", filename: "legacy.pdf" });
  });

  it("fails closed (404) when the object is on neither store", async () => {
    getVisibleDocument.mockResolvedValue({ id: DOC, blobUrl: "https://attacker9.public.blob.vercel-storage.com/x.pdf", name: "x.pdf", mime: "application/pdf" });
    signedReadUrl.mockResolvedValue(null);
    streamLegacyBlobResponse.mockResolvedValue(null);

    const res = await GET(req(), P);
    expect(res.status).toBe(404);
    expect(res.headers.get("location")).toBeNull();
  });
});
