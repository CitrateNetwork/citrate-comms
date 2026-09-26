import { describe, it, expect, vi, beforeEach } from "vitest";

// @vercel/blob is a network SDK; stub the two signing primitives so we can assert exactly
// how the helper scopes and expires an issued URL without touching the control plane.
const issueSignedToken = vi.fn();
const presignUrl = vi.fn();
const blobGet = vi.fn<(...a: unknown[]) => unknown>();
vi.mock("@vercel/blob", () => ({
  issueSignedToken: (...a: unknown[]) => issueSignedToken(...a),
  presignUrl: (...a: unknown[]) => presignUrl(...a),
  get: (...a: unknown[]) => blobGet(...a),
}));

import { signedReadUrl, signedUrlTtlSeconds, blobPathname, readBlobBytes, streamLegacyBlobResponse } from "./blob-signing";

// Assembled at runtime so secret scanners don't flag the fixture tokens.
const env = { BLOB_READ_WRITE_TOKEN: ["vercel_blob_rw", "store1", "fixture"].join("_") };
const envTwoStore = { ...env, BLOB_LEGACY_READ_WRITE_TOKEN: ["vercel_blob_rw", "oldpub", "fixture"].join("_") };
const PRIV = "https://store1.private.blob.vercel-storage.com";
const PUB = "https://store1.public.blob.vercel-storage.com";
const LEGACY = "https://oldpub.public.blob.vercel-storage.com";

beforeEach(() => {
  issueSignedToken.mockReset();
  presignUrl.mockReset();
  issueSignedToken.mockImplementation(async (opts: { validUntil: number }) => ({
    delegationToken: "dt",
    clientSigningToken: "cst",
    validUntil: opts.validUntil,
  }));
  presignUrl.mockImplementation(async (_t: unknown, opts: { pathname: string; validUntil: number }) => ({
    presignedUrl: `${PRIV}/${opts.pathname}?sig=MOCK&validUntil=${opts.validUntil}`,
  }));
});

describe("signedUrlTtlSeconds (configurable, clamped)", () => {
  it("defaults to 120s and clamps to [30, 600]", () => {
    expect(signedUrlTtlSeconds({})).toBe(120);
    expect(signedUrlTtlSeconds({ BLOB_SIGNED_URL_TTL_SECONDS: "300" })).toBe(300);
    expect(signedUrlTtlSeconds({ BLOB_SIGNED_URL_TTL_SECONDS: "5" })).toBe(30); // floor
    expect(signedUrlTtlSeconds({ BLOB_SIGNED_URL_TTL_SECONDS: "99999" })).toBe(600); // ceiling
    expect(signedUrlTtlSeconds({ BLOB_SIGNED_URL_TTL_SECONDS: "not-a-number" })).toBe(120);
  });
});

describe("blobPathname", () => {
  it("returns the store pathname without the leading slash", () => {
    expect(blobPathname(`${PRIV}/comms/w/a-1x2.pdf`)).toBe("comms/w/a-1x2.pdf");
    expect(blobPathname("not a url")).toBeNull();
  });
});

describe("signedReadUrl (short-lived, object-scoped, never the raw URL)", () => {
  it("issues a GET-only URL scoped to THIS object's pathname with a short TTL", async () => {
    const before = Date.now();
    const out = await signedReadUrl(`${PRIV}/comms/w/a.pdf`, { env });
    const after = Date.now();

    expect(out).not.toBeNull();
    // The delegation is scoped to the one object, read-only, and expires soon.
    expect(issueSignedToken).toHaveBeenCalledWith(
      expect.objectContaining({ pathname: "comms/w/a.pdf", operations: ["get"] }),
    );
    const issued = issueSignedToken.mock.calls[0]![0] as { validUntil: number };
    expect(issued.validUntil).toBeGreaterThanOrEqual(before + 120_000);
    expect(issued.validUntil).toBeLessThanOrEqual(after + 120_000);
    // The presign is bound to the same object + the private access class.
    expect(presignUrl).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ access: "private", operation: "get", pathname: "comms/w/a.pdf" }),
    );
    // The returned URL is the signed one — NOT the bare store URL.
    expect(out!.url).toContain("sig=MOCK");
    expect(out!.url.split("?")[0]).toBe(`${PRIV}/comms/w/a.pdf`);
    expect(out!.expiresAt).toBe(issued.validUntil);
  });

  it("honors a configured short TTL", async () => {
    const before = Date.now();
    await signedReadUrl(`${PRIV}/comms/w/a.pdf`, { env: { ...env, BLOB_SIGNED_URL_TTL_SECONDS: "60" } });
    const issued = issueSignedToken.mock.calls[0]![0] as { validUntil: number };
    expect(issued.validUntil).toBeGreaterThanOrEqual(before + 60_000);
    expect(issued.validUntil).toBeLessThanOrEqual(before + 61_000);
  });

  it("scopes distinct objects to distinct signed URLs (not a shared static token)", async () => {
    const a = await signedReadUrl(`${PRIV}/comms/w/a.pdf`, { env });
    const b = await signedReadUrl(`${PRIV}/comms/w/b.pdf`, { env });
    expect(a!.url).not.toBe(b!.url);
    expect(a!.url).toContain("comms/w/a.pdf");
    expect(b!.url).toContain("comms/w/b.pdf");
  });

  it("appends the download disposition without touching the signature", async () => {
    const out = await signedReadUrl(`${PRIV}/comms/w/a.pdf`, { env, download: true });
    const u = new URL(out!.url);
    expect(u.searchParams.get("download")).toBe("1");
    expect(u.searchParams.get("sig")).toBe("MOCK"); // signature params preserved
  });

  it("returns null (and signs nothing) for a non-private object", async () => {
    const out = await signedReadUrl(`${PUB}/comms/w/a.pdf`, { env });
    expect(out).toBeNull();
    expect(issueSignedToken).not.toHaveBeenCalled();
  });

  it("returns null for another store's private object", async () => {
    const out = await signedReadUrl("https://attacker9.private.blob.vercel-storage.com/x.pdf", { env });
    expect(out).toBeNull();
    expect(issueSignedToken).not.toHaveBeenCalled();
  });
});

describe("streamLegacyBlobResponse (transition-window path, no raw URL)", () => {
  const fetchMock = vi.fn<(...a: unknown[]) => Promise<Response>>();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("streams a recognized legacy object's bytes with the right disposition — never its URL", async () => {
    fetchMock.mockResolvedValue(new Response(new Blob(["hello"]), { status: 200, headers: { "content-type": "image/png", "content-length": "5" } }));
    const res = await streamLegacyBlobResponse(`${LEGACY}/legacy.png`, { download: false, mime: "image/png", filename: "legacy.png", env: envTwoStore });
    expect(res).not.toBeNull();
    expect(res!.status).toBe(200);
    expect(res!.headers.get("content-disposition")).toBe('inline; filename="legacy.png"');
    expect(res!.headers.get("cache-control")).toBe("private, no-store");
    expect(await res!.text()).toBe("hello");
    // The proxy fetched the object itself; it returns bytes, not the store URL.
    expect(fetchMock).toHaveBeenCalledWith(`${LEGACY}/legacy.png`, expect.anything());
  });

  it("uses attachment disposition for downloads and sanitizes the filename", async () => {
    fetchMock.mockResolvedValue(new Response(new Blob(["x"]), { status: 200 }));
    const res = await streamLegacyBlobResponse(`${LEGACY}/x`, { download: true, mime: "application/pdf", filename: 'a"b\n.pdf', env: envTwoStore });
    expect(res!.headers.get("content-disposition")).toBe('attachment; filename="a_b_.pdf"');
  });

  it("refuses (returns null, fetches nothing) a URL that is not a recognized legacy object", async () => {
    // A private object must go through signedReadUrl, not this helper.
    expect(await streamLegacyBlobResponse(`${PRIV}/comms/w/a.pdf`, { download: false, mime: null, filename: "a.pdf", env: envTwoStore })).toBeNull();
    // A foreign store is refused.
    expect(await streamLegacyBlobResponse("https://attacker9.public.blob.vercel-storage.com/a.pdf", { download: false, mime: null, filename: "a.pdf", env: envTwoStore })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("readBlobBytes (authenticated private read; legacy fallback; fail-closed)", () => {
  const fetchMock = vi.fn<(...a: unknown[]) => Promise<Response>>();
  beforeEach(() => {
    blobGet.mockReset();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("reads a private object via the authenticated get()", async () => {
    blobGet.mockResolvedValue({ statusCode: 200, stream: new Blob(["priv"]).stream(), blob: { size: 4 } });
    const buf = await readBlobBytes(`${PRIV}/comms/w/a.pdf`, undefined, envTwoStore);
    expect(buf?.toString()).toBe("priv");
    expect(blobGet).toHaveBeenCalledWith("comms/w/a.pdf", { access: "private" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads a legacy object via fetch", async () => {
    fetchMock.mockResolvedValue(new Response(new Blob(["old"]), { status: 200 }));
    const buf = await readBlobBytes(`${LEGACY}/legacy.txt`, undefined, envTwoStore);
    expect(buf?.toString()).toBe("old");
    expect(blobGet).not.toHaveBeenCalled();
  });

  it("fails closed for a URL on neither store", async () => {
    const buf = await readBlobBytes("https://attacker9.private.blob.vercel-storage.com/x", undefined, envTwoStore);
    expect(buf).toBeNull();
    expect(blobGet).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
