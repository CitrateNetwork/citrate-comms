/** PBA-L3c-026 (content-type half): readJson refuses non-JSON bodies on cookie-auth calls. */
import { describe, it, expect } from "vitest";
import { readJson, isJsonContentType } from "./http";

const mk = (h: Record<string, string>) => new Request("https://comms.example/api/x", { method: "POST", headers: h, body: '{"a":1}' });

describe("readJson content-type enforcement", () => {
  it("cookie-authenticated text/plain (CORS-simple) body is refused", async () => {
    expect(await readJson(mk({ cookie: "cc_oidc_id=a.b.c", "content-type": "text/plain" }))).toBeNull();
    expect(await readJson(mk({ cookie: "cc_oidc_refresh=r", "content-type": "application/x-www-form-urlencoded" }))).toBeNull();
    expect(await readJson(mk({ cookie: "cc_oidc_id=a.b.c" }))).toBeNull();
  });
  it("JSON (incl. +json and charset) is parsed; bearer and cookie-less callers keep working", async () => {
    expect(await readJson(mk({ cookie: "cc_oidc_id=a.b.c", "content-type": "application/json; charset=utf-8" }))).toEqual({ a: 1 });
    expect(await readJson(mk({ cookie: "cc_oidc_id=a.b.c", "content-type": "application/merge-patch+json" }))).toEqual({ a: 1 });
    expect(await readJson(mk({ cookie: "cc_oidc_id=a.b.c", authorization: "Bearer t", "content-type": "text/plain" }))).toEqual({ a: 1 });
    expect(await readJson(mk({ "content-type": "text/plain" }))).toEqual({ a: 1 });
    expect(await readJson(mk({ cookie: "other=1", "content-type": "text/plain" }))).toEqual({ a: 1 });
  });
  it("isJsonContentType", () => {
    expect(isJsonContentType("APPLICATION/JSON")).toBe(true);
    expect(isJsonContentType("application/jsonx")).toBe(false);
    expect(isJsonContentType("text/json")).toBe(false);
    expect(isJsonContentType("application/+json")).toBe(true);
    expect(isJsonContentType(null)).toBe(false);
  });
});
