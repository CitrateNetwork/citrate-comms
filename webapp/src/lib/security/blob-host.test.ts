import { describe, it, expect } from "vitest";
import { configuredBlobHost, isOwnBlobUrl } from "./blob-host";

// Assembled at runtime so secret scanners don't mistake the fixture for a credential.
const env = { BLOB_READ_WRITE_TOKEN: ["vercel_blob_rw", "AbC123xyz", "fixture"].join("_") };

describe("Blob host pinning (PBA-L3c-009)", () => {
  it("derives the store host from the read-write token", () => {
    expect(configuredBlobHost(env)).toBe("abc123xyz.public.blob.vercel-storage.com");
  });
  it("accepts only this store's https objects", () => {
    expect(isOwnBlobUrl("https://abc123xyz.public.blob.vercel-storage.com/comms/w/a.pdf", env)).toBe(true);
    expect(isOwnBlobUrl("https://attacker9.public.blob.vercel-storage.com/a.pdf", env)).toBe(false);
    expect(isOwnBlobUrl("http://abc123xyz.public.blob.vercel-storage.com/a.pdf", env)).toBe(false);
    expect(isOwnBlobUrl("https://abc123xyz.public.blob.vercel-storage.com.evil.io/a.pdf", env)).toBe(false);
    expect(isOwnBlobUrl("https://u:p@abc123xyz.public.blob.vercel-storage.com/a.pdf", env)).toBe(false);
    expect(isOwnBlobUrl("https://abc123xyz.public.blob.vercel-storage.com:8443/a.pdf", env)).toBe(false);
    expect(isOwnBlobUrl("not a url", env)).toBe(false);
  });
  it("fails closed with no store configured; BLOB_STORE_HOST overrides", () => {
    expect(isOwnBlobUrl("https://abc123xyz.public.blob.vercel-storage.com/a.pdf", {})).toBe(false);
    expect(configuredBlobHost({ ...env, BLOB_STORE_HOST: "Priv.Blob.Example" })).toBe("priv.blob.example");
    expect(configuredBlobHost({ BLOB_READ_WRITE_TOKEN: "garbage" })).toBeNull();
  });
});

describe("Blob host pinning — token parsing (mutation hardening)", () => {
  it("requires the token to START with the read-write prefix", () => {
    expect(configuredBlobHost({ BLOB_READ_WRITE_TOKEN: "xvercel_blob_rw_Abc_s" })).toBeNull();
    expect(configuredBlobHost({ BLOB_READ_WRITE_TOKEN: "vercel_blob_ro_Abc_s" })).toBeNull();
  });
});
