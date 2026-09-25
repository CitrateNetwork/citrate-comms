/**
 * Pin server-side Blob fetches to THIS deployment's store (PBA-L3c-009). A Vercel Blob
 * read-write token is `vercel_blob_rw_<storeId>_<secret>`, and that store's objects live
 * at `https://<storeid>.public.blob.vercel-storage.com/...`. Accepting any
 * `*.blob.vercel-storage.com` host let a caller register an attacker-controlled store's
 * object as a workspace document (fetched server-side, then proxied and shown inline).
 *
 * `BLOB_STORE_HOST` overrides the derived host (e.g. a private store's hostname).
 * Returns null when no store is configured — callers then refuse (fail closed).
 */
export function configuredBlobHost(env: Record<string, string | undefined> = process.env): string | null {
  const explicit = env.BLOB_STORE_HOST?.trim().toLowerCase();
  if (explicit) return explicit;
  const m = /^vercel_blob_rw_([A-Za-z0-9]+)_/.exec(env.BLOB_READ_WRITE_TOKEN ?? "");
  return m ? `${m[1]!.toLowerCase()}.public.blob.vercel-storage.com` : null;
}

/** True iff `url` is an https URL on this deployment's Blob store. */
export function isOwnBlobUrl(url: string, env: Record<string, string | undefined> = process.env): boolean {
  const host = configuredBlobHost(env);
  if (!host) return false;
  try {
    const u = new URL(url);
    return u.protocol === "https:" && u.hostname.toLowerCase() === host && !u.username && !u.password && (u.port === "" || u.port === "443");
  } catch {
    return false;
  }
}
