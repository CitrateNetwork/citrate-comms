/**
 * Safe parsing for ```chart (Vega-Lite) blocks (RR-2). Validates the fenced content is a
 * JSON object and REJECTS any spec that would fetch remote data (a `url` anywhere) — charts
 * must use inline `data.values` only, so a rendered chart can never trigger a network fetch
 * from the client. Pure (unit-tested); the renderer falls back to showing the code on failure.
 */
export type ChartParse = { ok: true; spec: Record<string, unknown> } | { ok: false };

function hasUrl(v: unknown, depth = 0): boolean {
  if (depth > 8 || v == null || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some((x) => hasUrl(x, depth + 1));
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (k.toLowerCase() === "url" && typeof val === "string") return true;
    if (hasUrl(val, depth + 1)) return true;
  }
  return false;
}

export function parseChartSpec(src: string): ChartParse {
  let o: unknown;
  try {
    o = JSON.parse(src);
  } catch {
    return { ok: false };
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) return { ok: false };
  if (hasUrl(o)) return { ok: false }; // no remote data — inline values only
  return { ok: true, spec: o as Record<string, unknown> };
}
