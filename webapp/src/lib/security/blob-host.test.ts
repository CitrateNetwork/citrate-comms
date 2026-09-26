import { describe, it, expect } from "vitest";
import {
  configuredPrivateBlobHost,
  configuredLegacyPublicBlobHost,
  isOwnBlobUrl,
  isOwnPrivateBlobUrl,
  isLegacyPublicBlobUrl,
} from "./blob-host";

// Assembled at runtime so secret scanners don't mistake the fixtures for credentials.
const PRIV_TOKEN = ["vercel_blob_rw", "PrivStore", "fixture"].join("_");
const LEGACY_TOKEN = ["vercel_blob_rw", "PubStore", "fixture"].join("_");
const env = { BLOB_READ_WRITE_TOKEN: PRIV_TOKEN, BLOB_LEGACY_READ_WRITE_TOKEN: LEGACY_TOKEN };

const PRIV = "https://privstore.private.blob.vercel-storage.com";
const LEGACY = "https://pubstore.public.blob.vercel-storage.com";

describe("Two-store host pinning (PBA-L3c-009 / ATT-HARDEN)", () => {
  it("derives each store host from its OWN token — never both from one", () => {
    expect(configuredPrivateBlobHost(env)).toBe("privstore.private.blob.vercel-storage.com");
    expect(configuredLegacyPublicBlobHost(env)).toBe("pubstore.public.blob.vercel-storage.com");
    // The private token does not imply a public host of the same id, and vice versa.
    expect(isOwnPrivateBlobUrl("https://privstore.public.blob.vercel-storage.com/a.pdf", env)).toBe(false);
    expect(isLegacyPublicBlobUrl("https://pubstore.private.blob.vercel-storage.com/a.pdf", env)).toBe(false);
  });

  it("classifies private, legacy and foreign objects", () => {
    expect(isOwnPrivateBlobUrl(`${PRIV}/comms/w/a.pdf`, env)).toBe(true);
    expect(isLegacyPublicBlobUrl(`${LEGACY}/legacy.pdf`, env)).toBe(true);
    expect(isOwnBlobUrl(`${PRIV}/comms/w/a.pdf`, env)).toBe(true);
    expect(isOwnBlobUrl(`${LEGACY}/legacy.pdf`, env)).toBe(true);

    // Another store's objects are rejected on every classifier.
    expect(isOwnBlobUrl("https://attacker9.private.blob.vercel-storage.com/a.pdf", env)).toBe(false);
    expect(isOwnBlobUrl("https://attacker9.public.blob.vercel-storage.com/a.pdf", env)).toBe(false);
    expect(isOwnPrivateBlobUrl("https://attacker9.private.blob.vercel-storage.com/a.pdf", env)).toBe(false);
  });

  it("a legacy public object is NOT a private object (routes it to the streaming path)", () => {
    expect(isOwnPrivateBlobUrl(`${LEGACY}/legacy.pdf`, env)).toBe(false);
  });

  it("applies URL-shape guards to both hosts", () => {
    for (const u of [
      `http://privstore.private.blob.vercel-storage.com/a.pdf`, // not https
      `https://u:p@privstore.private.blob.vercel-storage.com/a.pdf`, // creds
      `https://privstore.private.blob.vercel-storage.com:8443/a.pdf`, // port
      `https://privstore.private.blob.vercel-storage.com.evil.io/a.pdf`, // suffix host
      "not a url",
    ]) {
      expect(isOwnPrivateBlobUrl(u, env)).toBe(false);
      expect(isOwnBlobUrl(u, env)).toBe(false);
    }
  });

  it("honors explicit host overrides", () => {
    expect(configuredPrivateBlobHost({ ...env, BLOB_STORE_HOST: "Priv.Blob.Example" })).toBe("priv.blob.example");
    expect(configuredLegacyPublicBlobHost({ ...env, BLOB_LEGACY_PUBLIC_HOST: "Old.Blob.Example" })).toBe("old.blob.example");
  });

  it("fails closed when a store is unconfigured", () => {
    expect(configuredPrivateBlobHost({})).toBeNull();
    expect(configuredLegacyPublicBlobHost({})).toBeNull();
    expect(isOwnPrivateBlobUrl(`${PRIV}/a.pdf`, {})).toBe(false);
    expect(isLegacyPublicBlobUrl(`${LEGACY}/a.pdf`, {})).toBe(false);
    // With no legacy store configured (steady state after migration), legacy URLs are foreign.
    expect(isOwnBlobUrl(`${LEGACY}/a.pdf`, { BLOB_READ_WRITE_TOKEN: PRIV_TOKEN })).toBe(false);
  });

  it("requires the token to start with the read-write prefix", () => {
    expect(configuredPrivateBlobHost({ BLOB_READ_WRITE_TOKEN: "xvercel_blob_rw_Abc_s" })).toBeNull();
    expect(configuredPrivateBlobHost({ BLOB_READ_WRITE_TOKEN: "vercel_blob_ro_Abc_s" })).toBeNull();
    expect(configuredLegacyPublicBlobHost({ BLOB_LEGACY_READ_WRITE_TOKEN: "garbage" })).toBeNull();
  });
});
