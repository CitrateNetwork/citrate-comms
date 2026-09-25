/**
 * Safe parsing for ```chart (Vega-Lite) blocks (RR-2). Validates the fenced content is a
 * JSON object and REJECTS any spec that could reach the network (a `url`/`href` key of any
 * type anywhere, an image mark, or unboundedly deep nesting — PBA-L3c-021) — charts
 * must use inline `data.values` only, so a rendered chart can never trigger a network fetch
 * from the client. Pure (unit-tested); the renderer falls back to showing the code on failure.
 */
export type ChartParse = { ok: true; spec: Record<string, unknown> } | { ok: false };

const MAX_DEPTH = 16;
/** Keys that make Vega/Vega-Lite fetch or link out: `url` (data/lookup/image channel, in
 *  ANY form — a string OR an encoding object like {field:"u"}), `href` (link channel /
 *  mark property), and `loader`. PBA-L3c-021. */
const REMOTE_KEYS = new Set(["url", "href", "loader"]);

/**
 * True if the spec could reach the network: a remote key anywhere (any value type), an
 * `image` mark (which loads its url channel), or nesting too deep to inspect — which
 * fails CLOSED (previously a url below depth 8 slipped through).
 */
function hasRemote(v: unknown, depth = 0): boolean {
  if (v == null || typeof v !== "object") return false;
  if (depth > MAX_DEPTH) return true;
  if (Array.isArray(v)) return v.some((x) => hasRemote(x, depth + 1));
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    const key = k.toLowerCase();
    if (REMOTE_KEYS.has(key)) return true;
    if ((key === "mark" || key === "type") && typeof val === "string" && val.toLowerCase() === "image") return true;
    if (hasRemote(val, depth + 1)) return true;
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
  if (hasRemote(o)) return { ok: false }; // no remote data, images or links — inline values only
  return { ok: true, spec: o as Record<string, unknown> };
}
