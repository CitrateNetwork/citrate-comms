import { describe, it, expect } from "vitest";
import { parseSearxng, parseDuckduckgo, parseDuckduckgoLite, decodeEntities } from "./search";
import { isPrivateIp, isBlockedAddress, assertPublicUrl, extractReadable, BlockedUrlError, makeGuardedLookup, guardedGet, readCapped } from "./fetch";
import http from "node:http";
import type { AddressInfo } from "node:net";

describe("RES — search parsing", () => {
  it("parseSearxng keeps http(s) results, caps at k, maps content→snippet", () => {
    const json = {
      results: [
        { title: "A", url: "https://a.example.com", content: "alpha" },
        { title: "bad", url: "ftp://nope", content: "x" },
        { title: "B", url: "http://b.example.com", content: "beta" },
        { title: "C", url: "https://c.example.com", content: "gamma" },
      ],
    };
    const r = parseSearxng(json, 2);
    expect(r).toHaveLength(2);
    expect(r[0]).toEqual({ title: "A", url: "https://a.example.com", snippet: "alpha" });
    expect(r[1]!.url).toBe("http://b.example.com"); // ftp skipped
  });

  it("parseSearxng tolerates junk", () => {
    expect(parseSearxng(null, 5)).toEqual([]);
    expect(parseSearxng({ results: "nope" }, 5)).toEqual([]);
  });

  it("parseDuckduckgo decodes the uddg redirect and pulls snippets", () => {
    const target = "https://example.org/article?x=1&y=2";
    const html = `
      <a class="result__a" href="//duckduckgo.com/l/?uddg=${encodeURIComponent(target)}&rut=z">Title &amp; More</a>
      <a class="result__snippet" href="#">A <b>great</b> snippet</a>
    `;
    const r = parseDuckduckgo(html, 5);
    expect(r).toHaveLength(1);
    expect(r[0]!.url).toBe(target);
    expect(r[0]!.title).toBe("Title & More");
    expect(r[0]!.snippet).toBe("A great snippet");
  });

  it("parseDuckduckgoLite decodes uddg redirects, dedupes, caps at k", () => {
    const t1 = "https://a.example.com/x?p=1&q=2";
    const t2 = "https://b.example.com/y";
    const html = `
      <a rel="nofollow" href="//duckduckgo.com/l/?uddg=${encodeURIComponent(t1)}&rut=z">Alpha &amp; Co</a>
      <a rel="nofollow" href="//duckduckgo.com/l/?uddg=${encodeURIComponent(t1)}">Alpha dupe</a>
      <a rel="nofollow" href="//duckduckgo.com/l/?uddg=${encodeURIComponent(t2)}">Beta</a>
      <a href="https://duckduckgo.com/settings">settings (no uddg, skipped)</a>
    `;
    const r = parseDuckduckgoLite(html, 5);
    expect(r.map((x) => x.url)).toEqual([t1, t2]);
    expect(r[0]!.title).toBe("Alpha & Co");
  });

  it("decodeEntities handles named + numeric", () => {
    expect(decodeEntities("a &amp; b &#39;c&#39; &#x27;")).toBe("a & b 'c' &#x27;".replace("&#x27;", "'"));
  });
});

describe("RES — SSRF guard", () => {
  it("flags private / loopback / link-local / ULA ranges", () => {
    for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "0.0.0.0", "::1", "fe80::1", "fd00::1"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });
  it("allows public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]) {
      expect(isPrivateIp(ip), ip).toBe(false);
    }
  });

  // `isBlockedAddress` is the canonical name the runner egress client uses; assert the
  // alias blocks every non-public class and stays false for public addresses.
  it("isBlockedAddress blocks each non-public class and allows public addresses", () => {
    for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.1.5", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe"]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });
  it("rejects non-http schemes and internal hostnames", async () => {
    await expect(assertPublicUrl("file:///etc/passwd")).rejects.toBeInstanceOf(BlockedUrlError);
    await expect(assertPublicUrl("http://localhost/x")).rejects.toBeInstanceOf(BlockedUrlError);
    await expect(assertPublicUrl("http://foo.internal/x")).rejects.toBeInstanceOf(BlockedUrlError);
    await expect(assertPublicUrl("http://127.0.0.1/x")).rejects.toBeInstanceOf(BlockedUrlError);
    await expect(assertPublicUrl("http://169.254.169.254/latest/meta-data")).rejects.toBeInstanceOf(BlockedUrlError);
  });

  // CM2-B-B007: the guard was bypassed by bracketed IPv6, IPv4-mapped IPv6, the
  // CGNAT/benchmark ranges, and canonical-form IPv6. Table-driven so a new bypass
  // form extends the corpus, not the code (the finding's requested tripwire).
  it("blocks IPv6 bracketed/mapped/canonical and CGNAT/benchmark IPv4 bypasses", () => {
    for (const ip of [
      "[::1]", // bracketed loopback (URL.hostname keeps the brackets)
      "[::ffff:169.254.169.254]", // v4-mapped cloud metadata
      "[::ffff:a9fe:a9fe]", // same, canonical hex compression
      "[0:0:0:0:0:ffff:127.0.0.1]", // v4-mapped loopback, uncompressed
      "::ffff:127.0.0.1", // unbracketed v4-mapped loopback
      "100.64.1.5", // 100.64/10 CGNAT
      "198.18.0.1", // 198.18/15 benchmarking
      "192.0.0.1", // 192.0.0.0/24 IETF protocol assignments
    ]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
  });

  it("rejects the IPv6/CGNAT SSRF-bypass URLs at assertPublicUrl", async () => {
    for (const url of [
      "http://[::1]:9200/_cat/indices",
      "http://[::ffff:169.254.169.254]/latest/meta-data/",
      "http://[0:0:0:0:0:ffff:127.0.0.1]:8080/x",
      "http://100.64.1.5/",
      "http://198.18.0.1/",
    ]) {
      await expect(assertPublicUrl(url), url).rejects.toBeInstanceOf(BlockedUrlError);
    }
  });

  it("still allows genuine public IPv6", () => {
    expect(isPrivateIp("2606:2800:220:1:248:1893:25c8:1946")).toBe(false);
    expect(isPrivateIp("[2606:2800:220:1:248:1893:25c8:1946]")).toBe(false);
  });
});

describe("RES — readable extraction", () => {
  it("prefers <article>, strips script/style/nav, keeps paragraph text", () => {
    const html = `
      <html><head><title>My Page</title></head><body>
      <nav>home about</nav>
      <article>
        <h1>Headline</h1>
        <script>var x = 1;</script>
        <style>.a{}</style>
        <p>First paragraph.</p>
        <p>Second &amp; final.</p>
      </article>
      <footer>copyright</footer>
      </body></html>`;
    const { title, text } = extractReadable(html);
    expect(title).toBe("My Page");
    expect(text).toContain("Headline");
    expect(text).toContain("First paragraph.");
    expect(text).toContain("Second & final.");
    expect(text).not.toContain("var x");
    expect(text).not.toContain("home about");
    expect(text).not.toContain("copyright");
  });
});

describe("RES — SSRF guard: v4-translation ranges and connect-time lookup (PBA-L3c-025)", () => {
  it("refuses NAT64 / 6to4 / Teredo / documentation / site-local / multicast IPv6", () => {
    for (const ip of [
      "64:ff9b::a9fe:a9fe", // NAT64 → 169.254.169.254
      "64:ff9b::808:808", // NAT64 even to a public v4 (fail-closed)
      "64:ff9b:1::a00:1", // local-use NAT64 → 10.0.0.1
      "2002:a9fe:a9fe::1", // 6to4 → 169.254.169.254
      "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
      "2001:db8::1",
      "fec0::1",
      "ff02::1",
      "100::1",
      "::ffff:0:a9fe:a9fe", // RFC 2765 IPv4-translated → 169.254.169.254
      "::ffff:0:808:808", // translated even to a public v4 (fail-closed)
      "0:0:0:0:ffff:0:7f00:1",
    ]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
    // a genuine global unicast address that merely STARTS with 2001 is still public
    expect(isPrivateIp("2001:4860:4860::8888")).toBe(false);
  });

  it("the connect-time lookup refuses a name that re-resolves to a private address (DNS rebinding)", async () => {
    let calls = 0;
    // first resolution (validation) public, second (connect) private — the rebinding shape
    const flaky = (_h: string, _o: { all: true }, cb: (e: NodeJS.ErrnoException | null, a: { address: string; family: number }[]) => void) => {
      calls++;
      cb(null, [{ address: calls === 1 ? "93.184.216.34" : "127.0.0.1", family: 4 }]);
    };
    const lookup = makeGuardedLookup(flaky);
    const first = await new Promise<string>((res, rej) => lookup("rebind.test", {}, (e, a) => (e ? rej(e) : res(a as string))));
    expect(first).toBe("93.184.216.34");
    await expect(new Promise((res, rej) => lookup("rebind.test", {}, (e, a) => (e ? rej(e) : res(a))))).rejects.toBeInstanceOf(BlockedUrlError);
    // mixed answer sets are refused too; `all` returns the vetted list
    const mixed = makeGuardedLookup((_h, _o, cb) => cb(null, [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.5", family: 4 }]));
    await expect(new Promise((res, rej) => mixed("x.test", { all: true }, (e, a) => (e ? rej(e) : res(a))))).rejects.toBeInstanceOf(BlockedUrlError);
    const ok = makeGuardedLookup((_h, _o, cb) => cb(null, [{ address: "93.184.216.34", family: 4 }]));
    const all = await new Promise((res, rej) => ok("x.test", { all: true }, (e, a) => (e ? rej(e) : res(a))));
    expect(all).toEqual([{ address: "93.184.216.34", family: 4 }]);
  });

  it("a real socket using the guarded lookup never connects to a private address", async () => {
    let hits = 0;
    const srv = http.createServer((_q, r) => {
      hits++;
      r.end("internal secret");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    const lookup = makeGuardedLookup((_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }]));
    const err = await new Promise<unknown>((resolve) => {
      const q = http.get({ host: "metadata.rebind.test", port, path: "/", lookup: lookup as never }, () => resolve(null));
      q.on("error", resolve);
    });
    await new Promise<void>((r) => srv.close(() => r()));
    expect(err).toBeInstanceOf(BlockedUrlError);
    expect(hits).toBe(0);
  });
});

describe("RES — node:http transport plumbing (PBA-L3c-025)", () => {
  it("guardedGet returns status/location/content-type without following redirects; readCapped bounds the body", async () => {
    const srv = http.createServer((q, r) => {
      if (q.url === "/r") {
        r.writeHead(302, { location: "/final" });
        return r.end();
      }
      r.writeHead(200, { "content-type": "text/html" });
      r.end("<html><title>T</title><article><p>" + "x".repeat(5000) + "</p></article></html>");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    // a permissive lookup ONLY for this plumbing test (the real one refuses loopback)
    const permissive = (_h: string, o: { all?: boolean }, cb: (e: null, a: unknown, f?: number) => void) =>
      o && o.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
    const ctrl = new AbortController();
    const red = await guardedGet(new URL(`http://plumb.test:${port}/r`), ctrl.signal, permissive);
    expect(red.status).toBe(302);
    expect(red.location).toBe("/final");
    red.res.resume();
    const ok = await guardedGet(new URL(`http://plumb.test:${port}/final`), ctrl.signal, permissive);
    expect(ok.status).toBe(200);
    expect(ok.contentType).toContain("text/html");
    const body = await readCapped(ok.res, 100);
    expect(body.length).toBe(100);
    const full = await guardedGet(new URL(`http://plumb.test:${port}/final`), ctrl.signal, permissive);
    expect(extractReadable(await readCapped(full.res, 1_000_000)).title).toBe("T");
    await new Promise<void>((r) => srv.close(() => r()));
  });
});

describe("RES — SSRF guard boundaries (PBA-L3c-025 mutation hardening)", () => {
  it("addresses NEXT TO the refused prefixes stay public", () => {
    for (const ip of ["2606:ff9b::1", "64:ff9a::1", "2606:0:1::1", "2606:db8::1", "2001:1::1", "100:0:0:1::1", "100:1::1", "2003::1", "2606::1", "2a00::1", "::fffe:0:808:808", "1::ffff:0:808:808"]) {
      expect(isPrivateIp(ip), ip).toBe(false);
    }
  });

  it("the connect-time lookup asks for ALL addresses, passes resolver errors through, and refuses an empty answer", async () => {
    const seen: unknown[] = [];
    const strict = makeGuardedLookup((_h, o, cb) => {
      seen.push(o);
      cb(null, [{ address: "93.184.216.34", family: 4 }]);
    });
    await new Promise((res) => strict("x.test", undefined as never, (_e, a) => res(a)));
    expect(seen).toEqual([{ all: true }]);
    const dnsErr = Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    const failing = makeGuardedLookup((_h, _o, cb) => cb(dnsErr, []));
    await expect(new Promise((res, rej) => failing("x.test", {}, (e, a) => (e ? rej(e) : res(a))))).rejects.toBe(dnsErr);
    const empty = makeGuardedLookup((_h, _o, cb) => cb(null, []));
    await expect(new Promise((res, rej) => empty("x.test", {}, (e, a) => (e ? rej(e) : res(a))))).rejects.toThrow("host did not resolve");
    const priv = makeGuardedLookup((_h, _o, cb) => cb(null, [{ address: "10.1.2.3", family: 4 }]));
    await expect(new Promise((res, rej) => priv("x.test", {}, (e, a) => (e ? rej(e) : res(a))))).rejects.toThrow("resolves to a private address");
    const fam = await new Promise<number | undefined>((res) => strict("x.test", 4 as never, (_e, _a, f) => res(f)));
    expect(fam).toBe(4);
  });
});
