/**
 * RES — keyless web search provider seam (PLANSET/RESEARCH_keyless_websearch.md).
 *
 * Backends, keyless-first, in priority order:
 *   1. SearXNG  (DEFAULT) — self-hosted metasearch, clean JSON, $0/query, env SEARXNG_URL.
 *   2. DuckDuckGo HTML — light keyless fallback (rate-limited), parsed from the lite HTML.
 *
 * Returns a stable shape regardless of backend so the agent tool never has to care which
 * one answered. When nothing is configured/reachable, returns available:false (fail-soft —
 * the agent says "search is unavailable", it does not crash the turn).
 *
 * This runs on the BFF, NOT the runner: search works the moment SearXNG is up, with no
 * sandbox required. The runner is only the escalation path for JS-heavy page *fetches*.
 */

export interface WebResult {
  title: string;
  url: string;
  snippet: string;
}
export interface WebSearchResult {
  results: WebResult[];
  provider: "searxng" | "duckduckgo" | "none";
  available: boolean;
  note?: string;
}

const TIMEOUT_MS = 8000;

/** fetch with an abort timeout — a slow engine must never hang an agent turn. */
async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: "follow" });
  } finally {
    clearTimeout(timer);
  }
}

/** Decode the few HTML entities that show up in titles/snippets (no DOM dependency). */
export function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
}

function stripTags(s: string): string {
  return decodeEntities(s.replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim();
}

/** SearXNG JSON: { results: [{ title, url, content }] }. */
export function parseSearxng(json: unknown, k: number): WebResult[] {
  const arr = (json as { results?: unknown[] })?.results;
  if (!Array.isArray(arr)) return [];
  const out: WebResult[] = [];
  for (const r of arr) {
    const o = r as Record<string, unknown>;
    const url = typeof o.url === "string" ? o.url : "";
    const title = typeof o.title === "string" ? o.title : "";
    if (!url || !/^https?:\/\//i.test(url)) continue;
    out.push({ title: title || url, url, snippet: typeof o.content === "string" ? o.content : "" });
    if (out.length >= k) break;
  }
  return out;
}

/**
 * DuckDuckGo HTML endpoint: result anchors carry class="result__a" with an href that is a
 * `/l/?uddg=<encoded-target>` redirect; the snippet is in class="result__snippet".
 * We pull the real target out of the uddg param. Pure-regex (no DOM dep).
 */
export function parseDuckduckgo(html: string, k: number): WebResult[] {
  const out: WebResult[] = [];
  const anchor = /<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
  const snip = /<a[^>]*class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/g;
  const snippets: string[] = [];
  let sm: RegExpExecArray | null;
  while ((sm = snip.exec(html))) snippets.push(stripTags(sm[1]!));
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = anchor.exec(html)) && out.length < k) {
    let href = decodeEntities(m[1]!);
    const uddg = /[?&]uddg=([^&]+)/.exec(href);
    if (uddg) href = decodeURIComponent(uddg[1]!);
    if (href.startsWith("//")) href = "https:" + href;
    if (!/^https?:\/\//i.test(href)) continue;
    out.push({ title: stripTags(m[2]!) || href, url: href, snippet: snippets[i] ?? "" });
    i++;
  }
  return out;
}

async function searchSearxng(query: string, k: number): Promise<WebResult[] | null> {
  const base = process.env.SEARXNG_URL;
  if (!base) return null;
  try {
    const u = new URL("/search", base);
    u.searchParams.set("q", query);
    u.searchParams.set("format", "json");
    u.searchParams.set("safesearch", "1");
    const res = await fetchWithTimeout(u.toString(), { headers: { accept: "application/json" } });
    if (!res.ok) return null;
    return parseSearxng(await res.json(), k);
  } catch {
    return null;
  }
}

async function searchDuckduckgo(query: string, k: number): Promise<WebResult[] | null> {
  try {
    const u = new URL("https://html.duckduckgo.com/html/");
    u.searchParams.set("q", query);
    const res = await fetchWithTimeout(u.toString(), {
      headers: { "user-agent": "Mozilla/5.0 (compatible; CitrateComms/1.0)", accept: "text/html" },
    });
    if (!res.ok) return null;
    return parseDuckduckgo(await res.text(), k);
  } catch {
    return null;
  }
}

/** Run a keyless web search across the configured backends (SearXNG → DuckDuckGo). */
export async function searchWeb(query: string, k = 5): Promise<WebSearchResult> {
  const n = Math.min(Math.max(k, 1), 10);

  const sx = await searchSearxng(query, n);
  if (sx && sx.length) return { results: sx, provider: "searxng", available: true };

  const ddg = await searchDuckduckgo(query, n);
  if (ddg && ddg.length) return { results: ddg, provider: "duckduckgo", available: true };

  return {
    results: [],
    provider: "none",
    available: false,
    note: "Web search is unavailable — set SEARXNG_URL (self-hosted, keyless) or check connectivity.",
  };
}
