/**
 * Pin server-side Blob fetches to THIS deployment's stores (PBA-L3c-009). A Vercel Blob
 * read-write token is `vercel_blob_rw_<storeId>_<secret>`, and a store's objects live at
 * `https://<storeid>.<access>.blob.vercel-storage.com/...` where `<access>` is `public` or
 * `private` and is FIXED when the store is created. Accepting any `*.blob.vercel-storage.com`
 * host let a caller register an attacker-controlled store's object as a workspace document.
 *
 * Two stores, recognized independently (never both derived from one token):
 *  - PRIMARY (private): `BLOB_READ_WRITE_TOKEN` → `<id>.private.blob.vercel-storage.com`
 *    (or `BLOB_STORE_HOST` override). All new attachments land here and are served via
 *    short-lived signed URLs.
 *  - LEGACY (public): `BLOB_LEGACY_READ_WRITE_TOKEN` → `<id>.public.blob.vercel-storage.com`
 *    (or `BLOB_LEGACY_PUBLIC_HOST` override). The pre-existing public store, kept only until
 *    its objects are migrated into the private store and it is deleted. Legacy objects are
 *    streamed through the proxy (never handed to the client as a URL) during that window.
 *
 * Each getter returns null when its store is unconfigured — callers then refuse (fail closed).
 */
function storeIdFromToken(token: string | undefined): string | null {
  const m = /^vercel_blob_rw_([A-Za-z0-9]+)_/.exec(token ?? "");
  return m ? m[1]!.toLowerCase() : null;
}

/** This deployment's PRIVATE store host (`<storeid>.private.…`), or the explicit override. */
export function configuredPrivateBlobHost(env: Record<string, string | undefined> = process.env): string | null {
  const explicit = env.BLOB_STORE_HOST?.trim().toLowerCase();
  if (explicit) return explicit;
  const id = storeIdFromToken(env.BLOB_READ_WRITE_TOKEN);
  return id ? `${id}.private.blob.vercel-storage.com` : null;
}

/** The LEGACY public store host (`<storeid>.public.…`), or the explicit override; null if
 *  no legacy store is configured (the steady state once migration is complete). */
export function configuredLegacyPublicBlobHost(env: Record<string, string | undefined> = process.env): string | null {
  const explicit = env.BLOB_LEGACY_PUBLIC_HOST?.trim().toLowerCase();
  if (explicit) return explicit;
  const id = storeIdFromToken(env.BLOB_LEGACY_READ_WRITE_TOKEN);
  return id ? `${id}.public.blob.vercel-storage.com` : null;
}

function isCanonicalStoreUrl(url: string, host: string | null): boolean {
  if (!host) return false;
  try {
    const u = new URL(url);
    return (
      u.protocol === "https:" &&
      u.hostname.toLowerCase() === host &&
      !u.username &&
      !u.password &&
      (u.port === "" || u.port === "443")
    );
  } catch {
    return false;
  }
}

/** True iff `url` is an https URL on this deployment's PRIVATE Blob store. */
export function isOwnPrivateBlobUrl(url: string, env: Record<string, string | undefined> = process.env): boolean {
  return isCanonicalStoreUrl(url, configuredPrivateBlobHost(env));
}

/** True iff `url` is an https URL on this deployment's LEGACY public Blob store. */
export function isLegacyPublicBlobUrl(url: string, env: Record<string, string | undefined> = process.env): boolean {
  return isCanonicalStoreUrl(url, configuredLegacyPublicBlobHost(env));
}

/** True iff `url` is an https URL on either of this deployment's stores (private or legacy). */
export function isOwnBlobUrl(url: string, env: Record<string, string | undefined> = process.env): boolean {
  return isOwnPrivateBlobUrl(url, env) || isLegacyPublicBlobUrl(url, env);
}
