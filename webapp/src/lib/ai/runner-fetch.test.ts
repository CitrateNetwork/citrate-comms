/**
 * Egress restriction for the runner web-fetch path (`runnerWebFetch`).
 *
 * These tests exercise the actual connecting client, not just the address helper: a
 * non-public target is refused, and a public URL that redirects to a non-public address is
 * refused AT THE HOP (the redirect target is re-validated before the next connect). A
 * genuinely public destination is allowed through.
 */
import { afterEach, describe, expect, it } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runnerWebFetch, BlockedUrlError } from "./runner-fetch";
import type { AddressResolver } from "@/lib/research/fetch";

// A connect-time lookup that always points node:http at loopback, so a fake public host in
// the URL is actually served by the local test server. Injected ONLY in tests.
const connectToLoopback = (_h: string, o: { all?: boolean }, cb: (e: null, a: unknown, f?: number) => void) =>
  o && o.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
// A resolver that answers "public" for the pre-connect / per-hop validation of a hostname.
const resolvePublic: AddressResolver = async () => [{ address: "93.184.216.34", family: 4 }];

describe("runnerWebFetch — egress restricted to public destinations", () => {
  it("refuses non-public literal targets before any connection", async () => {
    for (const url of [
      "http://169.254.169.254/",
      "http://127.0.0.1/",
      "http://10.0.0.1/",
      "http://172.16.0.1/",
      "http://192.168.1.1/",
      "http://100.64.1.5/",
      "http://[::1]/",
      "http://[::ffff:127.0.0.1]/",
      "http://[fe80::1]/",
      "http://[64:ff9b::a9fe:a9fe]/",
    ]) {
      await expect(runnerWebFetch(url), url).rejects.toBeInstanceOf(BlockedUrlError);
    }
  });

  it("refuses non-http(s) schemes", async () => {
    for (const url of ["file:///etc/passwd", "gopher://127.0.0.1/", "ftp://10.0.0.1/", "data:text/html,x"]) {
      await expect(runnerWebFetch(url), url).rejects.toBeInstanceOf(BlockedUrlError);
    }
  });
});

describe("runnerWebFetch — redirect handling over a real socket", () => {
  let srv: http.Server;
  let port = 0;

  afterEach(async () => {
    if (srv) await new Promise<void>((r) => srv.close(() => r()));
  });

  async function listen(handler: http.RequestListener) {
    srv = http.createServer(handler);
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    port = (srv.address() as AddressInfo).port;
  }

  it("refuses a destination that redirects to a non-public address at the hop", async () => {
    let secretHit = 0;
    await listen((q, r) => {
      if (q.url === "/redir") {
        r.writeHead(302, { location: "http://10.0.0.1/secret" });
        return r.end();
      }
      secretHit++;
      r.writeHead(200, { "content-type": "text/html" });
      r.end("<html><title>leaked</title><article><p>internal</p></article></html>");
    });
    await expect(
      runnerWebFetch(`http://public.test:${port}/redir`, { lookup: connectToLoopback, resolve: resolvePublic }),
    ).rejects.toBeInstanceOf(BlockedUrlError);
    expect(secretHit).toBe(0); // never followed the redirect to the private target
  });

  it("allows a genuinely public destination and returns its readable text", async () => {
    await listen((_q, r) => {
      r.writeHead(200, { "content-type": "text/html" });
      r.end("<html><title>Public</title><article><p>hello world</p></article></html>");
    });
    const res = await runnerWebFetch(`http://public.test:${port}/`, { lookup: connectToLoopback, resolve: resolvePublic });
    expect(res.title).toBe("Public");
    expect(res.text).toContain("hello world");
  });
});
