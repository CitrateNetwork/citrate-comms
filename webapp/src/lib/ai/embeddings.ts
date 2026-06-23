/**
 * Embeddings client (COMMS-AGENTS S2). Calls the inference gateway's OpenAI-compatible
 * `/v1/embeddings` (the bge model) to turn text into vectors for pgvector recall in the
 * NeonMemoryStore. BEST-EFFORT: if the gateway/embeddings model isn't configured or
 * reachable, returns null and the caller falls back to lexical recall — so the knowledge
 * graph ships either way and lights up automatically once the gateway is wired (see the
 * inference-gateway registration handoff).
 *
 * Reuses the same gateway base URL + `cgk_` key as chat (provider.ts).
 */
import { EMBEDDING_DIM } from "@/lib/db/schema";

const TIMEOUT_MS = 8000;

function endpoint(): { url: string; apiKey: string | undefined } | null {
  const mode = (process.env.CITRATE_INFERENCE_MODE ?? "gateway").toLowerCase();
  const base =
    mode === "local"
      ? (process.env.CITRATE_INFERENCE_URL ?? "http://127.0.0.1:8080/v1")
      : (process.env.CITRATE_GATEWAY_URL ?? "https://infer.citrate.ai/v1");
  const apiKey = process.env.CITRATE_GATEWAY_API_KEY ?? process.env.CITRATE_INFERENCE_API_KEY;
  // Fail-closed posture matches provider.ts: no key in gateway mode ⇒ don't call.
  if (mode === "gateway" && !apiKey) return null;
  return { url: `${base.replace(/\/$/, "")}/embeddings`, apiKey };
}

export function embedModel(): string {
  return process.env.CITRATE_EMBED_MODEL ?? "bge-m3";
}

/** True only when an embeddings endpoint is plausibly configured (no network probe). */
export function embeddingsConfigured(): boolean {
  return endpoint() !== null;
}

/**
 * Embed one or more texts. Returns one vector per input, or null on any failure
 * (unconfigured, timeout, non-200, shape mismatch) — callers degrade to lexical recall.
 */
export async function embed(texts: string[]): Promise<number[][] | null> {
  const ep = endpoint();
  if (!ep || texts.length === 0) return null;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(ep.url, {
      method: "POST",
      headers: { "content-type": "application/json", ...(ep.apiKey ? { authorization: `Bearer ${ep.apiKey}` } : {}) },
      body: JSON.stringify({ model: embedModel(), input: texts }),
      cache: "no-store",
      signal: ac.signal,
    });
    if (!r.ok) return null;
    const json = (await r.json()) as { data?: { embedding?: number[] }[] };
    const out = (json.data ?? []).map((d) => d.embedding ?? []);
    // Only accept well-formed vectors of the expected width.
    if (out.length !== texts.length || out.some((v) => v.length !== EMBEDDING_DIM)) return null;
    return out;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Embed a single text (convenience). */
export async function embedOne(text: string): Promise<number[] | null> {
  const out = await embed([text]);
  return out?.[0] ?? null;
}
