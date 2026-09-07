import { describe, it, expect } from "vitest";
import { parseSearxng, parseDuckduckgo, parseDuckduckgoLite, decodeEntities } from "./search";
import { isPrivateIp, assertPublicUrl, extractReadable, BlockedUrlError } from "./fetch";

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
