/**
 * The request gate (src/proxy.ts): CSP on every response (PBA-L3c-008) and the
 * same-origin guard on cookie-authenticated API mutations (PBA-L3c-026).
 */
import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import proxy from "./proxy";
import { buildCsp } from "@/lib/security/csp";

const COOKIE = "cc_oidc_id=aaa.bbb.ccc";
const mk = (path: string, init: { method?: string; headers?: Record<string, string> } = {}) =>
  new NextRequest(`https://comms.example${path}`, { method: init.method ?? "GET", headers: { host: "comms.example", ...(init.headers ?? {}) } });

describe("proxy: Content-Security-Policy (PBA-L3c-008)", () => {
  it("every page response carries a nonce'd CSP, forwarded to SSR too", async () => {
    const res = await proxy(mk("/w/acme/comms"));
    const csp = res.headers.get("content-security-policy");
    expect(csp).toBeTruthy();
    const nonce = /'nonce-([^']+)'/.exec(csp!)?.[1];
    expect(nonce).toBeTruthy();
    expect(res.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
    expect(res.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
    const again = (await proxy(mk("/w/acme/comms"))).headers.get("content-security-policy");
    expect(again).not.toBe(csp); // fresh nonce per request
  });

  it("public/auth surfaces get the CSP too (unsubscribe, auth callback)", async () => {
    for (const p of ["/unsubscribe?t=x", "/auth/callback?code=1"]) {
      expect((await proxy(mk(p))).headers.get("content-security-policy"), p).toContain("script-src");
    }
  });

  it("the policy never allows inline or eval'd script, framing, plugins or base hijack", () => {
    const csp = buildCsp("N0nce", { NEXT_PUBLIC_OIDC_ISSUER: "https://auth.example/oidc" });
    const script = /script-src ([^;]+)/.exec(csp)![1]!;
    expect(script).toContain("'nonce-N0nce'");
    expect(script).toContain("'strict-dynamic'");
    expect(script).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toMatch(/connect-src 'self' https:\/\/auth\.example(;|$)/);
  });
});

describe("proxy: cross-site mutation guard (PBA-L3c-026)", () => {
  const api = "/api/workspaces/w1/accounts";
  it("refuses a cross-site, cookie-authenticated POST", async () => {
    const res = await proxy(mk(api, { method: "POST", headers: { cookie: COOKIE, "sec-fetch-site": "cross-site" } }));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "cross-origin request refused" });
  });
  it("refuses a same-site SIBLING subdomain and a foreign Origin without fetch-metadata", async () => {
    expect((await proxy(mk(api, { method: "PATCH", headers: { cookie: COOKIE, "sec-fetch-site": "same-site" } }))).status).toBe(403);
    expect((await proxy(mk(api, { method: "DELETE", headers: { cookie: COOKIE, origin: "https://evil.example" } }))).status).toBe(403);
  });
  it("admits same-origin mutations, safe methods, bearer-token and cookie-less callers", async () => {
    const ok = (r: Response) => r.status !== 403;
    expect(ok(await proxy(mk(api, { method: "POST", headers: { cookie: COOKIE, "sec-fetch-site": "same-origin" } })))).toBe(true);
    expect(ok(await proxy(mk(api, { method: "POST", headers: { cookie: COOKIE, origin: "https://comms.example" } })))).toBe(true);
    expect(ok(await proxy(mk(api, { method: "GET", headers: { cookie: COOKIE, "sec-fetch-site": "cross-site" } })))).toBe(true);
    expect(ok(await proxy(mk(api, { method: "POST", headers: { cookie: COOKIE, authorization: "Bearer x", "sec-fetch-site": "cross-site" } })))).toBe(true);
    expect(ok(await proxy(mk("/api/unsubscribe", { method: "POST", headers: { "sec-fetch-site": "cross-site" } })))).toBe(true);
  });
});
