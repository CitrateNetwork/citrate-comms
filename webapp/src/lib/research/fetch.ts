/**
 * RES — keyless page fetch + readable-text extraction (PLANSET/RESEARCH_keyless_websearch.md).
 *
 * Static path runs on the BFF: SSRF-guarded fetch → strip boilerplate → readable text.
 * Dependency-free extraction (no DOM/native deps); the upgrade path for JS-heavy pages is
 * the runner's Playwright fetch (escalation), wired in the tool layer.
 *
 * SSRF posture (fail-closed): only http/https, and the resolved IP must be public — private,
 * loopback, link-local and unique-local ranges are refused so an agent can't be steered into
 * the internal network or cloud metadata (169.254.169.254).
 */
import { lookup } from "node:dns/promises";

export interface ReadablePage {
  url: string;
  title: string;
  text: string;
  truncated: boolean;
  available: boolean;
  note?: string;
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

/** Is a dotted-quad / v6 literal in a private, loopback, link-local or ULA range? */
export function isPrivateIp(ip: string): boolean {
  // IPv4
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10) return true;
    if (a === 127) return true; // loopback
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true; // multicast/reserved
    return false;
  }
  // IPv6
  const lo = ip.toLowerCase();
  if (lo === "::1" || lo === "::") return true;
  if (lo.startsWith("fe80")) return true; // link-local
  if (lo.startsWith("fc") || lo.startsWith("fd")) return true; // unique-local
  if (lo.startsWith("::ffff:")) return isPrivateIp(lo.slice(7)); // v4-mapped
  return false;
}

/** Validate scheme + host, then DNS-resolve and reject private targets (SSRF guard). */
export async function assertPublicUrl(raw: string): Promise<URL> {
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
    if (isPrivateIp(host)) throw new BlockedUrlError("private address not allowed");
    return u;
  }
  let addrs;
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new BlockedUrlError("host did not resolve");
  }
  if (addrs.length === 0) throw new BlockedUrlError("host did not resolve");
  for (const a of addrs) if (isPrivateIp(a.address)) throw new BlockedUrlError("resolves to a private address");
  return u;
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

/** Fetch a public URL and return its readable text (static path; SSRF-guarded). */
export async function fetchReadable(raw: string): Promise<ReadablePage> {
  let u: URL;
  try {
    u = await assertPublicUrl(raw);
  } catch (e) {
    return { url: raw, title: "", text: "", truncated: false, available: false, note: (e as Error).message };
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(u.toString(), {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "user-agent": "Mozilla/5.0 (compatible; CitrateComms/1.0)", accept: "text/html,*/*" },
    });
    if (!res.ok) return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: `fetch failed (${res.status})` };
    const ctype = res.headers.get("content-type") ?? "";
    if (!/text\/html|text\/plain|application\/xhtml/i.test(ctype)) {
      return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: `unsupported content-type (${ctype || "unknown"})` };
    }
    const raw_html = (await res.text()).slice(0, MAX_BYTES);
    const { title, text } = extractReadable(raw_html);
    const truncated = text.length > MAX_TEXT;
    return { url: u.toString(), title, text: truncated ? text.slice(0, MAX_TEXT) : text, truncated, available: true };
  } catch (e) {
    const aborted = (e as Error)?.name === "AbortError";
    return { url: u.toString(), title: "", text: "", truncated: false, available: false, note: aborted ? "fetch timed out" : "fetch error" };
  } finally {
    clearTimeout(timer);
  }
}
