/**
 * Short-lived, object-scoped signed reads for private-store attachments (ATT-HARDEN).
 *
 * Attachments are written to a PRIVATE Vercel Blob store (`put(..., { access: "private" })`),
 * so an object is never retrievable just by holding its URL. The download proxy authorizes
 * the viewer per document and only THEN calls {@link signedReadUrl} — which mints a fresh
 * signed URL scoped to that single object's pathname, GET-only, expiring after a short,
 * configurable TTL. There is no static, shareable token: each issuance is a new HMAC over
 * `{ pathname, operation=get, validUntil }`, so a captured link stops working once the TTL
 * lapses and cannot be replayed against a different object.
 *
 * Server-only (imports `@vercel/blob`). Never import from a client component.
 */
import { get, issueSignedToken, presignUrl } from "@vercel/blob";
import { isLegacyPublicBlobUrl, isOwnPrivateBlobUrl } from "./blob-host";

/** Default signed-read lifetime (seconds) when unconfigured. */
const DEFAULT_TTL_SECONDS = 120;
/** Clamp bounds so a misconfiguration can't mint a long-lived or already-dead URL. */
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 600;

/**
 * Signed-read lifetime in seconds. Configurable via `BLOB_SIGNED_URL_TTL_SECONDS`,
 * clamped to [30, 600]; defaults to 120s. Kept short so an issued URL is useful for the
 * immediate view/download and little else.
 */
export function signedUrlTtlSeconds(env: Record<string, string | undefined> = process.env): number {
  const raw = Number(env.BLOB_SIGNED_URL_TTL_SECONDS);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_TTL_SECONDS;
  return Math.min(Math.max(Math.trunc(raw), MIN_TTL_SECONDS), MAX_TTL_SECONDS);
}

/** The store pathname of a Blob object URL (leading slash stripped), or null. */
export function blobPathname(blobUrl: string): string | null {
  try {
    const p = new URL(blobUrl).pathname.replace(/^\/+/, "");
    return p || null;
  } catch {
    return null;
  }
}

export interface SignedRead {
  /** A short-lived URL that resolves to the object's bytes and nothing else. */
  url: string;
  /** Absolute expiry (ms since epoch) enforced by the CDN. */
  expiresAt: number;
}

/**
 * Mint a short-lived, GET-only signed URL for a single private-store object. Returns null
 * when `blobUrl` is not on this deployment's private store (the caller then serves the
 * object another way or refuses). The signature covers `{ pathname, operation, validUntil }`;
 * `download` only appends the CDN download-disposition hint and is NOT part of the signed
 * canonical string, so it never affects verification.
 */
export async function signedReadUrl(
  blobUrl: string,
  opts: { download?: boolean; ttlSeconds?: number; env?: Record<string, string | undefined> } = {},
): Promise<SignedRead | null> {
  const env = opts.env ?? process.env;
  if (!isOwnPrivateBlobUrl(blobUrl, env)) return null;
  const pathname = blobPathname(blobUrl);
  if (!pathname) return null;

  const ttl = opts.ttlSeconds ?? signedUrlTtlSeconds(env);
  const validUntil = Date.now() + ttl * 1000;

  // Scope the delegation to THIS object + read only, expiring at validUntil.
  const token = await issueSignedToken({ pathname, operations: ["get"], validUntil });
  const { presignedUrl } = await presignUrl(
    { clientSigningToken: token.clientSigningToken, delegationToken: token.delegationToken },
    { access: "private", operation: "get", pathname, validUntil: token.validUntil },
  );

  let url = presignedUrl;
  if (opts.download) {
    const u = new URL(presignedUrl);
    u.searchParams.set("download", "1");
    url = u.toString();
  }
  return { url, expiresAt: token.validUntil };
}

/**
 * Read a stored attachment's bytes server-side (for RAG text extraction). Authenticates to
 * the private store via `get(..., { access: "private" })`; reads a legacy public object of
 * this deployment via a direct fetch. Refuses any URL that is on neither store (fail closed).
 * `maxBytes` caps buffering (returns null if the object is larger). Returns null on any read
 * failure — callers treat text extraction as best-effort.
 */
export async function readBlobBytes(
  blobUrl: string,
  maxBytes?: number,
  env: Record<string, string | undefined> = process.env,
): Promise<Buffer | null> {
  try {
    if (isOwnPrivateBlobUrl(blobUrl, env)) {
      const pathname = blobPathname(blobUrl);
      if (!pathname) return null;
      const r = await get(pathname, { access: "private" });
      if (!r || r.statusCode !== 200) return null;
      if (maxBytes !== undefined && r.blob.size > maxBytes) return null;
      return await streamToBuffer(r.stream, maxBytes);
    }
    if (!isLegacyPublicBlobUrl(blobUrl, env)) return null; // fail closed on foreign hosts
    // Legacy public object of this deployment (pre-migration): directly fetchable.
    const r = await fetch(blobUrl, { cache: "no-store" });
    if (!r.ok) return null;
    if (maxBytes !== undefined) {
      const len = Number(r.headers.get("content-length") ?? 0);
      if (len > maxBytes) return null;
    }
    return Buffer.from(await r.arrayBuffer());
  } catch {
    return null;
  }
}

/**
 * Stream a LEGACY public object's bytes back through the proxy (transition-window path), so
 * the raw store URL is never handed to the client. Returns null when `blobUrl` is not a
 * recognized legacy object of this deployment, or the object can't be read. Private objects
 * are served via {@link signedReadUrl} instead and must not reach this helper.
 */
export async function streamLegacyBlobResponse(
  blobUrl: string,
  opts: { download: boolean; mime: string | null; filename: string; env?: Record<string, string | undefined> },
): Promise<Response | null> {
  const env = opts.env ?? process.env;
  if (!isLegacyPublicBlobUrl(blobUrl, env)) return null;
  let upstream: Response;
  try {
    upstream = await fetch(blobUrl, { cache: "no-store" });
  } catch {
    return null;
  }
  if (!upstream.ok || !upstream.body) return null;

  const safeName = opts.filename.replace(/["\r\n\\]/g, "_");
  const headers = new Headers();
  headers.set("content-type", opts.mime || upstream.headers.get("content-type") || "application/octet-stream");
  const len = upstream.headers.get("content-length");
  if (len) headers.set("content-length", len);
  headers.set("content-disposition", `${opts.download ? "attachment" : "inline"}; filename="${safeName}"`);
  headers.set("cache-control", "private, no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(upstream.body, { status: 200, headers });
}

async function streamToBuffer(stream: ReadableStream<Uint8Array>, maxBytes?: number): Promise<Buffer | null> {
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (maxBytes !== undefined && total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}
