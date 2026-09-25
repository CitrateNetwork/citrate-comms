/**
 * Exact-policy + edge tests for the CSP builder and the CSRF predicate (PBA-L3c-008 /
 * PBA-L3c-026), written to kill the mutants the proxy-level tests leave alive.
 */
import { describe, it, expect } from "vitest";
import { buildCsp, newNonce } from "./csp";
import { isSameOrigin, isForgedMutation } from "./csrf";

describe("buildCsp — exact policy", () => {
  it("matches the reviewed policy byte for byte (dev, issuer configured)", () => {
    expect(buildCsp("N", { NEXT_PUBLIC_OIDC_ISSUER: "https://auth.example/oidc", NODE_ENV: "development" })).toBe(
      "default-src 'self'; script-src 'self' 'nonce-N' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: blob: https:; media-src 'self' blob: https:; font-src 'self' data:; " +
        "connect-src 'self' https://auth.example; frame-src 'none'; worker-src 'self' blob:; manifest-src 'self'; " +
        "object-src 'none'; base-uri 'self'; form-action 'self' https://auth.example; frame-ancestors 'none'",
    );
  });
  it("production adds upgrade-insecure-requests; a missing or bad issuer adds nothing", () => {
    expect(buildCsp("N", { NODE_ENV: "production" })).toMatch(/; upgrade-insecure-requests$/);
    const bad = buildCsp("N", { NEXT_PUBLIC_OIDC_ISSUER: "not a url" });
    expect(bad).toContain("connect-src 'self';");
    expect(bad).toContain("form-action 'self';");
    expect(bad).not.toContain("upgrade-insecure-requests");
  });
  it("nonces are fresh 128-bit base64", () => {
    const a = newNonce();
    expect(a).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(newNonce()).not.toBe(a);
  });
});

const r = (method: string, h: Record<string, string>) => new Request("https://comms.example/api/x", { method, headers: h });

describe("isSameOrigin / isForgedMutation — edges", () => {
  it("fetch-metadata: same-origin and none pass, same-site and cross-site fail", () => {
    expect(isSameOrigin(r("POST", { "sec-fetch-site": "same-origin" }))).toBe(true);
    expect(isSameOrigin(r("POST", { "sec-fetch-site": "none" }))).toBe(true);
    expect(isSameOrigin(r("POST", { "sec-fetch-site": "same-site" }))).toBe(false);
    expect(isSameOrigin(r("POST", { "sec-fetch-site": "cross-site", origin: "https://comms.example", host: "comms.example" }))).toBe(false);
  });
  it("Origin fallback: host must match; no host or a malformed origin fails; no headers = non-browser", () => {
    expect(isSameOrigin(r("POST", { origin: "https://comms.example", host: "comms.example" }))).toBe(true);
    expect(isSameOrigin(r("POST", { origin: "https://comms.example", "x-forwarded-host": "comms.example", host: "internal:3000" }))).toBe(true);
    expect(isSameOrigin(r("POST", { origin: "https://comms.example" }))).toBe(false);
    expect(isSameOrigin(r("POST", { origin: "::::", host: "comms.example" }))).toBe(false);
    expect(isSameOrigin(r("POST", {}))).toBe(true);
  });
  it("only cookie-carrying, bearer-less, non-safe /api calls are judged", () => {
    const x = { "sec-fetch-site": "cross-site" };
    expect(isForgedMutation(r("POST", x), "/api/w", true)).toBe(true);
    expect(isForgedMutation(r("HEAD", x), "/api/w", true)).toBe(false);
    expect(isForgedMutation(r("OPTIONS", x), "/api/w", true)).toBe(false);
    expect(isForgedMutation(r("GET", x), "/api/w", true)).toBe(false);
    expect(isForgedMutation(r("POST", x), "/w/acme", true)).toBe(false);
    expect(isForgedMutation(r("POST", x), "/api/w", false)).toBe(false);
    expect(isForgedMutation(r("POST", { ...x, authorization: "Bearer t" }), "/api/w", true)).toBe(false);
    expect(isForgedMutation(r("post", x), "/api/w", true)).toBe(true);
  });
});
