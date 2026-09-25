/**
 * Integration-test global setup (PBA-R2): runs the REAL Drizzle migrations against a
 * REAL Postgres named by TEST_DATABASE_URL, after dropping and recreating the `public`
 * schema so every run starts from an empty, fully-migrated database.
 *
 * pgvector: CI uses the pgvector/pgvector image, so the extension is real there. A local
 * Postgres without pgvector (e.g. Homebrew) gets a copy of the migrations with the
 * `vector(1024)` columns rewritten to `real[]`. Nothing in the web tier queries vectors
 * without embeddings configured (RAG falls back to lexical), so authz behaviour is the
 * same either way.
 *
 * Refuses to run against anything that does not look like a throwaway test database,
 * because it drops the schema.
 */
import { cpSync, mkdtempSync, readdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";

const MIGRATIONS = fileURLToPath(new URL("../lib/db/migrations", import.meta.url));

export default async function setup() {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) throw new Error("TEST_DATABASE_URL is not set (integration tests need a throwaway Postgres)");
  const dbName = new URL(url).pathname.replace(/^\//, "");
  if (!/test|_it|ci/i.test(dbName)) throw new Error(`refusing to reset non-test database "${dbName}"`);

  const sql = postgres(url, { max: 1, onnotice: () => {} });
  try {
    await sql.unsafe("DROP SCHEMA IF EXISTS public CASCADE; DROP SCHEMA IF EXISTS drizzle CASCADE; CREATE SCHEMA public;");
    let hasVector = true;
    try {
      await sql.unsafe("CREATE EXTENSION IF NOT EXISTS vector");
    } catch {
      hasVector = false;
    }
    let folder = MIGRATIONS;
    let tmp: string | null = null;
    if (!hasVector) {
      tmp = mkdtempSync(join(tmpdir(), "comms-mig-"));
      cpSync(MIGRATIONS, tmp, { recursive: true });
      for (const f of readdirSync(tmp).filter((n) => n.endsWith(".sql"))) {
        const p = join(tmp, f);
        const s = readFileSync(p, "utf8")
          .replace(/CREATE EXTENSION IF NOT EXISTS vector;(--> statement-breakpoint)?/g, "")
          .replace(/vector\(\d+\)/g, "real[]");
        writeFileSync(p, s);
      }
      folder = tmp;
    }
    await migrate(drizzle(sql), { migrationsFolder: folder });
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  } finally {
    await sql.end();
  }
}
