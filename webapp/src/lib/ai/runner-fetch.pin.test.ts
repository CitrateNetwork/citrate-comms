/**
 * The DEFAULT connecting client (no test injection) must re-check the destination at
 * connect time. Pre-connect validation is told the host is public; the platform resolver
 * the socket uses answers loopback. The fetch must be refused as blocked, and the local
 * server must never be reached.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";

vi.mock("node:dns", async (orig) => {
  const actual = (await orig()) as typeof import("node:dns");
  const lookup = (host: string, opts: unknown, cb: (e: NodeJS.ErrnoException | null, a: unknown, f?: number) => void) => {
    if (host === "pinned.test") {
      const all = typeof opts === "object" && opts !== null && (opts as { all?: boolean }).all;
      return all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
    }
    return (actual.lookup as unknown as (...a: unknown[]) => void)(host, opts, cb);
  };
  return { ...actual, default: { ...actual, lookup }, lookup };
});

import { fetchReadable } from "@/lib/research/fetch";
import { runnerWebFetch, BlockedUrlError } from "./runner-fetch";
import * as runner from "./runner";

describe("runner web-fetch: connect-time address check on the default client", () => {
  let srv: http.Server;
  let port = 0;
  let hits = 0;

  beforeAll(async () => {
    srv = http.createServer((_q, r) => {
      hits++;
      r.writeHead(200, { "content-type": "text/html" });
      r.end("<html><title>internal</title><article><p>internal</p></article></html>");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    port = (srv.address() as AddressInfo).port;
  });
  afterAll(async () => {
    await new Promise<void>((r) => srv.close(() => r()));
  });

  const publicAtValidation = async () => [{ address: "93.184.216.34", family: 4 }];

  it("refuses when the connect-time answer differs from the validated one", async () => {
    const page = await fetchReadable(`http://pinned.test:${port}/`, { resolve: publicAtValidation });
    expect(page.blocked).toBe(true);
    await expect(runnerWebFetch(`http://pinned.test:${port}/`, { resolve: publicAtValidation })).rejects.toBeInstanceOf(
      BlockedUrlError,
    );
    expect(hits).toBe(0);
  });

  it("the runner client exposes no raw-URL web-fetch delegation", () => {
    expect((runner as Record<string, unknown>).webFetch).toBeUndefined();
  });
});
