/**
 * RES — keyless page fetch + readable-text extraction (PLANSET/RESEARCH_keyless_websearch.md).
 *
 * Static path runs on the BFF: SSRF-guarded fetch → strip boilerplate → readable text.
 * Dependency-free extraction (no DOM/native deps); the upgrade path for JS-heavy pages is
 * the runner's Playwright fetch (escalation), wired in the tool layer.
 *
 * SSRF posture (fail-closed): only http/https, and the resolved IP must be public — private,
 * loopback, link-local, unique-local and v4-translation (NAT64/6to4/Teredo) ranges are
 * refused so an agent can't be steered into the internal network or cloud metadata
 * (169.254.169.254). The check is re-run at CONNECT time by a pinned lookup, closing the
 * DNS-rebinding window between validation and connection (PBA-L3c-025).
 */
import { lookup } from "node:dns/promises";
import { lookup as dnsLookupCb, type LookupAddress } from "node:dns";
import http from "node:http";
import https from "node:https";
import type { IncomingMessage } from "node:http";

export interface ReadablePage {
  url: string;
  title: string;
  text: string;
  truncated: boolean;
  available: boolean;
  note?: string;
  /**
   * True ⇒ the fetch was refused by the SSRF guard (private/blocked target),
   * as opposed to merely empty/unsupported/timed-out. Callers MUST NOT escalate a
   * blocked page to a less-guarded fetcher (CM2-B-B006): a security refusal is a
   * refusal, never a signal that "static extraction was too thin".
   */
  blocked?: boolean;
}

const TIMEOUT_MS = 10000;
const MAX_BYTES = 2_000_000; // 2MB of HTML is plenty for article text
const MAX_TEXT = 20_000; // chars handed to the model

export class BlockedUrlError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "BlockedUrlError";
  }
}

/** Is a dotted-quad IPv4 in a private / loopback / link-local / reserved range? */
function isPrivateIpv4(a: number, b: number): boolean {
  if (a === 10) return true;
  if (a === 127) return true; // loopback
  if (a === 0) return true; // "this network"
  if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT (RFC 6598)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking (RFC 2544)
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 IETF protocol assignments
  if (a >= 224) return true; // multicast + 240/4 reserved
  return false;
}

/**
 * Expand an IPv6 literal to its 8 16-bit groups, resolving `::` and any embedded
 * IPv4 tail (dotted or the v4-mapped hex form). Returns null if unparseable.
 */
function expandIpv6(ip: string): number[] | null {
  let s = ip;
  // Embedded dotted IPv4 tail (e.g. ::ffff:169.254.169.254): fold into two hex groups.
  let v4tail: [number, number] | null = null;
  const lastColon = s.lastIndexOf(":");
  if (lastColon >= 0) {
    const tail = s.slice(lastColon + 1);
    const dm = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(tail);
    if (dm) {
      const o = dm.slice(1).map(Number);
      if (o.some((n) => n > 255)) return null;
      v4tail = [(o[0]! << 8) | o[1]!, (o[2]! << 8) | o[3]!];
      s = s.slice(0, lastColon + 1) + "0:0";
    } else if (tail.includes(".")) {
      return null; // malformed dotted tail
    }
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tailParts = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : null;
  let groups: string[];
  if (tailParts === null) {
    groups = head;
  } else {
    const missing = 8 - head.length - tailParts.length;
    if (missing < 0) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...tailParts];
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => (g === "" ? 0 : parseInt(g, 16)));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  if (v4tail) {
    nums[6] = v4tail[0];
    nums[7] = v4tail[1];
  }
  return nums;
}

/**
 * Is a dotted-quad or IPv6 literal in a private, loopback, link-local, ULA or
 * otherwise non-public range? Bracket-tolerant, canonical-form-tolerant, and
 * resolves IPv4-mapped / IPv4-compatible IPv6 to the embedded IPv4 before deciding
 * (CM2-B-B007). Anything it cannot parse is treated as private (fail-closed).
 */
export function isPrivateIp(ip: string): boolean {
  // Tolerate a bracketed IPv6 literal (URL.hostname keeps the brackets).
  let s = ip.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  // Drop an IPv6 zone id (fe80::1%eth0).
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);

  // IPv4 dotted quad.
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true; // malformed → fail-closed
    return isPrivateIpv4(o[0]!, o[1]!);
  }

  // IPv6 (only if it actually contains a colon).
  if (s.includes(":")) {
    const g = expandIpv6(s.toLowerCase());
    if (!g) return true; // unparseable IPv6 → fail-closed
    // Unspecified :: and loopback ::1
    if (g.every((x) => x === 0)) return true;
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true;
    // Link-local fe80::/10
    if ((g[0]! & 0xffc0) === 0xfe80) return true;
    // Unique-local fc00::/7
    if ((g[0]! & 0xfe00) === 0xfc00) return true;
    // PBA-L3c-025: translation/tunnel prefixes that embed (or route to) an IPv4 target —
    // NAT64 64:ff9b::/96 and local-use 64:ff9b:1::/48 (RFC 6052/8215), 6to4 2002::/16,
    // Teredo 2001::/32 — plus discard-only 100::/64, documentation 2001:db8::/32,
    // deprecated site-local fec0::/10 and multicast ff00::/8. Refused outright (fail-closed):
    // a public-looking v6 address must not be a door into a private v4 network.
    if (g[0] === 0x64 && g[1] === 0xff9b) return true;
    if (g[0] === 0x2002) return true;
    if (g[0] === 0x2001 && g[1] === 0) return true;
    if (g[0] === 0x2001 && g[1] === 0x0db8) return true;
    if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true;
    if ((g[0]! & 0xffc0) === 0xfec0) return true;
    if ((g[0]! & 0xff00) === 0xff00) return true;
    // IPv4-mapped ::ffff:0:0/96 and IPv4-compatible ::/96 → judge by the embedded v4.
    // RFC 2765 IPv4-translated ::ffff:0:0:0/96 (::ffff:0:a.b.c.d) — refused outright,
    // like the other translation prefixes (verifier, informational).
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0xffff && g[5] === 0) return true;
    const mapped = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0);
    if (mapped && (g[6] !== 0 || g[7] !== 0)) {
      return isPrivateIpv4(g[6]! >> 8, g[6]! & 0xff) || isPrivateIpv4(g[7]! >> 8, g[7]! & 0xff);
    }
    return false;
  }

  // Not an IP literal we recognize (e.g. a raw integer host) → let the caller's URL
  // normalization have already run; treat an unrecognized numeric-looking host as private.
  return true;
}

/**
 * Canonical name for the shared address-range decision: is this literal IP one the fetch
 * layer must refuse (i.e. not a public/global-unicast destination)? Backed by the same
 * logic as `isPrivateIp`, kept as an alias so one tested implementation covers both the
 * static fetcher and the egress-restricted runner fetch. Fail-closed: anything unparseable
 * is treated as blocked.
 */
export const isBlockedAddress = isPrivateIp;

/**
 * Optional resolver used by {@link assertPublicUrl} to look up a hostname's addresses.
 * Defaults to the platform resolver; injectable so the fetch path can be exercised
 * deterministically in tests without real DNS.
 */
export type AddressResolver = (host: string, opts: { all: true }) => Promise<LookupAddress[]>;

/** Validate scheme + host, then resolve and reject non-public targets. */
export async function assertPublicUrl(raw: string, resolve: AddressResolver = lookup as unknown as AddressResolver): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new BlockedUrlError("invalid url");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new BlockedUrlError("only http(s) is allowed");
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) {
    throw new BlockedUrlError("host not allowed");
  }
  // If the host is an IP literal, check it directly; else resolve all addresses.
  if (/^[\d.]+$/.test(host) || host.includes(":")) {
    if (isBlockedAddress(host)) throw new BlockedUrlError("private address not allowed");
    return u;
  }
  let addrs;
  try {
    addrs = await resolve(host, { all: true });
  } catch {
    throw new BlockedUrlError("host did not resolve");
  }
  if (addrs.length === 0) throw new BlockedUrlError("host did not resolve");
  for (const a of addrs) if (isBlockedAddress(a.address)) throw new BlockedUrlError("resolves to a private address");
  return u;
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;
type Resolver = (hostname: string, options: { all: true }, cb: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void) => void;

/**
 * A `lookup` for node:http(s) that re-validates EVERY address at CONNECT time
 * (PBA-L3c-025). assertPublicUrl resolves once up front; without this the socket's own
 * resolution could return a different (private) address — DNS rebinding. With it, the
 * socket can only ever connect to an address that passed isPrivateIp.
 */
export function makeGuardedLookup(resolve: Resolver = dnsLookupCb as unknown as Resolver) {
  return (hostname: string, options: { all?: boolean } | number | undefined, cb: LookupCb): void => {
    resolve(hostname, { all: true }, (err, addrs) => {
      if (err) return cb(err, "", 4);
      if (!addrs || addrs.length === 0) return cb(new BlockedUrlError("host did not resolve") as NodeJS.ErrnoException, "", 4);
      if (addrs.some((a) => isPrivateIp(a.address))) return cb(new BlockedUrlError("resolves to a private address") as NodeJS.ErrnoException, "", 4);
      if (typeof options === "object" && options?.all) return cb(null, addrs);
      cb(null, addrs[0]!.address, addrs[0]!.family);
    });
  };
}

const guardedLookup = makeGuardedLookup();

interface RawResponse {
  status: number;
  location: string | null;
  contentType: string;
  res: IncomingMessage;
}

/** One GET over node:http(s) with the connect-time SSRF guard; no automatic redirects. */
export function guardedGet(u: URL, signal: AbortSignal, lookup: unknown = guardedLookup): Promise<RawResponse> {
  const mod = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      u,
      {
        method: "GET",
        lookup: lookup as never,
        signal,
        headers: { "user-agent": "Mozilla/5.0 (compatible; CitrateComms/1.0)", accept: "text/html,*/*" },
      },
      (res) =>
        resolve({
          status: res.statusCode ?? 0,
          location: typeof res.headers.location === "string" ? res.headers.location : null,
          contentType: String(res.headers["content-type"] ?? ""),
          res,
        }),
    );
    req.on("error", reject);
    req.end();
  });
}

/** Read at most `max` bytes of a response body as UTF-8, then stop the transfer. */
export function readCapped(res: IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let n = 0;
    res.on("data", (c: Buffer) => {
      if (n >= max) return;
      chunks.push(c);
      n += c.length;
      if (n >= max) {
        res.destroy();
        resolve(Buffer.concat(chunks).subarray(0, max).toString("utf8"));
      }
    });
    res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    res.on("error", (e) => (n >= max ? undefined : reject(e)));
  });
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
}

/** Crude but keyless readable extraction: drop non-content elements, keep block text. */
export function extractReadable(html: string): { title: string; text: string } {
  const titleM = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const title = titleM ? decodeEntities(titleM[1]!.replace(/<[^>]*>/g, "")).trim() : "";

  let body = html;
  // Prefer <main>/<article> when present — much higher signal than the whole page.
  const main = /<(?:article|main)[^>]*>([\s\S]*?)<\/(?:article|main)>/i.exec(html);
  if (main) body = main[1]!;

  body = body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<(?:nav|header|footer|aside|form)[\s\S]*?<\/(?:nav|header|footer|aside|form)>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    // Turn block boundaries into newlines so paragraphs survive.
    .replace(/<\/(?:p|div|li|h[1-6]|tr|section|br)[^>]*>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ");

  const text = decodeEntities(body)
    .split("\n")
    .map((l) => l.replace(/[ \t]+/g, " ").trim())
    .filter(Boolean)
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return { title, text };
}

const MAX_REDIRECTS = 5;

/**
 * Options for {@link fetchReadable}. Both hooks default to the guarded platform behavior;
 * they exist so the connecting path (address validation + per-hop re-validation + the
 * connect-time pinned lookup) can be driven deterministically in tests. Production callers
 * pass nothing and get the pinned, egress-restricted client.
 */
export interface FetchReadableOptions {
  /** Connect-time lookup handed to node:http(s); defaults to the pinned guarded lookup. */
  lookup?: unknown;
  /** Resolver used by the pre-connect / per-hop address validation. */
  resolve?: AddressResolver;
}

/** Fetch a public URL and return its readable text through the guarded, pinned client. */
export async function fetchReadable(raw: string, opts: FetchReadableOptions = {}): Promise<ReadablePage> {
  const connectLookup = opts.lookup ?? guardedLookup;
  const resolve = opts.resolve;
  let u: URL;
  try {
    u = await assertPublicUrl(raw, resolve);
  } catch (e) {
    // A refusal is flagged `blocked` so callers never fall through to a less-guarded fetch.
    return { url: raw, title: "", text: "", truncated: false, available: false, blocked: true, note: (e as Error).message };
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    // Follow redirects manually so EVERY hop is re-validated before we connect —
    // `redirect: "follow"` would let an allowed host 30x into a non-public destination.
    // Bounded to MAX_REDIRECTS. The connect itself uses the pinned lookup, so the socket
    // can only ever reach an address that passed validation.
    let res: RawResponse;
    let hops = 0;
    for (;;) {
      res = await guardedGet(u, ctrl.signal, connectLookup);
      if (res.status >= 300 && res.status < 400 && res.location) {
        res.res.resume(); // discard the redirect body
        if (++hops > MAX_REDIRECTS) {
          return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: "too many redirects" };
        }
        const loc = new URL(res.location, u).toString();
        try {
          u = await assertPublicUrl(loc, resolve); // re-validate the redirect target
        } catch (e) {
          return { url: loc, title: "", text: "", truncated: false, available: false, blocked: true, note: (e as Error).message };
        }
        continue;
      }
      break;
    }
    if (res.status < 200 || res.status >= 300) {
      res.res.resume();
      return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: `fetch failed (${res.status})` };
    }
    const ctype = res.contentType;
    if (!/text\/html|text\/plain|application\/xhtml/i.test(ctype)) {
      res.res.resume();
      return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: `unsupported content-type (${ctype || "unknown"})` };
    }
    const raw_html = await readCapped(res.res, MAX_BYTES);
    const { title, text } = extractReadable(raw_html);
    const truncated = text.length > MAX_TEXT;
    return { url: u.toString(), title, text: truncated ? text.slice(0, MAX_TEXT) : text, truncated, available: true };
  } catch (e) {
    // A connect-time SSRF refusal (the pinned lookup) is a refusal, never "thin".
    if (e instanceof BlockedUrlError) return { url: u.toString(), title: "", text: "", truncated: false, available: false, blocked: true, note: e.message };
    const aborted = (e as Error)?.name === "AbortError";
    return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: aborted ? "fetch timed out" : "fetch error" };
  } finally {
    clearTimeout(timer);
  }
}
