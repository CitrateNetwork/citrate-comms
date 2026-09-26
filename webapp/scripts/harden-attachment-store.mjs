/**
 * Attachment store hardening — migrate legacy public objects into the private store
 * (ATT-HARDEN). Two-store migration.
 *
 * Vercel Blob access is fixed at store CREATION and cannot be changed afterward, so
 * privatizing existing attachments requires a SEPARATE private store. New uploads already
 * go to the private store (`BLOB_READ_WRITE_TOKEN`); the objects created before that change
 * still live in the old PUBLIC store and remain retrievable by URL. This script:
 *   (a) enumerates + COUNTS the objects in the legacy public store;
 *   (b) with --apply, for each object: reads it (legacy token) → `put`s it into the private
 *       store under a NEW RANDOM pathname (so the old pathname is never valid again, and no
 *       one can re-derive it) → repoints the matching `documents.blob_url` row → `del`s the
 *       public original (legacy token) so the old public URL stops resolving;
 *   (c) is a DRY RUN by default: it only counts and prints a plan, mutating nothing.
 *
 * After every object is migrated and the counts reconcile, DELETE the old public store.
 *
 * ── [team to run against prod] ────────────────────────────────────────────────
 * Run by an operator against production, never from a dev/CI checkout. Requires BOTH tokens:
 *   BLOB_READ_WRITE_TOKEN=...            # NEW private store (destination; also prod default)
 *   BLOB_LEGACY_READ_WRITE_TOKEN=...     # OLD public store (source)
 *   DATABASE_URL_UNPOOLED=... (or DATABASE_URL)   # to repoint documents.blob_url
 *
 *   node scripts/harden-attachment-store.mjs            # dry run: count + plan
 *   node scripts/harden-attachment-store.mjs --apply    # perform the migration
 *
 * Idempotent: objects already migrated are gone from the legacy store, so re-running is safe.
 */
import { randomUUID } from "node:crypto";
import { list, put, del } from "@vercel/blob";

const APPLY = process.argv.includes("--apply");
const LEGACY = process.env.BLOB_LEGACY_READ_WRITE_TOKEN;
const PRIVATE = process.env.BLOB_READ_WRITE_TOKEN;

if (!LEGACY) {
  console.error("BLOB_LEGACY_READ_WRITE_TOKEN (old public store) is not set — nothing to enumerate.");
  process.exit(1);
}
if (APPLY && !PRIVATE) {
  console.error("--apply requires BLOB_READ_WRITE_TOKEN (new private store) as the destination.");
  process.exit(1);
}

function extOf(pathname) {
  const i = pathname.lastIndexOf(".");
  return i === -1 ? "" : pathname.slice(i);
}

async function initDb() {
  const url = process.env.DATABASE_URL_UNPOOLED || process.env.DATABASE_URL;
  if (!url) return null;
  const { default: postgres } = await import("postgres");
  return postgres(url, { max: 1, prepare: false, idle_timeout: 10, connect_timeout: 20 });
}

async function main() {
  let sql = null;
  if (APPLY) {
    sql = await initDb();
    if (!sql) {
      console.error("--apply requires DATABASE_URL(_UNPOOLED) to repoint documents.blob_url.");
      process.exit(1);
    }
  }

  let cursor;
  let legacyObjects = 0;
  let migrated = 0;
  let repointed = 0;
  const failures = [];

  do {
    const page = await list({ token: LEGACY, cursor, limit: 1000 });
    for (const blob of page.blobs) {
      legacyObjects++;
      if (!APPLY) continue;
      try {
        // Read the legacy public object (its URL is public, no auth needed).
        const res = await fetch(blob.url, { cache: "no-store" });
        if (!res.ok) throw new Error(`read ${res.status}`);
        const body = Buffer.from(await res.arrayBuffer());
        // Write into the private store under a fresh random pathname.
        const dest = `comms/migrated/${randomUUID()}${extOf(blob.pathname)}`;
        const put_ = await put(dest, body, {
          access: "private",
          token: PRIVATE,
          addRandomSuffix: false,
          contentType: res.headers.get("content-type") || undefined,
        });
        // Repoint the DB row, then delete the public original.
        const upd = await sql`UPDATE documents SET blob_url = ${put_.url} WHERE blob_url = ${blob.url}`;
        repointed += upd.count ?? 0;
        await del(blob.url, { token: LEGACY });
        migrated++;
      } catch (e) {
        failures.push({ pathname: blob.pathname, error: String(e?.message ?? e) });
      }
    }
    cursor = page.hasMore ? page.cursor : undefined;
  } while (cursor);

  console.log(JSON.stringify({
    mode: APPLY ? "apply" : "dry-run",
    legacyPublicObjects: legacyObjects,
    migratedToPrivate: migrated,
    documentRowsRepointed: repointed,
    failures,
  }, null, 2));

  if (!APPLY) {
    console.log(`\n[team to run against prod] ${legacyObjects} legacy public object(s) in the old store. Re-run with --apply to migrate, then delete the old public store.`);
  }
  if (failures.length) process.exitCode = 1;
  if (sql) await sql.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
