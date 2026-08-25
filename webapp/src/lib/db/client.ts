/**
 * Postgres Drizzle client (DO Managed Postgres). Server-only. Fail-closed: the app
 * refuses to construct a client without DATABASE_URL.
 *
 * DATABASE_URL should point at the DO **connection pooler** (transaction mode) — Vercel
 * opens a connection per invocation, so the pooler multiplexes them onto the small
 * primary. `prepare: false` is REQUIRED for a transaction-mode pooler (named prepared
 * statements don't survive across pooled transactions). `max: 1` keeps each warm
 * serverless instance to a single upstream connection; the pooler does the real pooling.
 */
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

let _db: ReturnType<typeof drizzle<typeof schema>> | null = null;

export function db() {
  if (_db) return _db;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set");
  const sql = postgres(url, {
    prepare: false, // transaction-pooler safe
    max: 1, // serverless: one upstream conn per instance; the DO pooler fans out
    idle_timeout: 20,
    connect_timeout: 15,
  });
  _db = drizzle(sql, { schema });
  return _db;
}

export { schema };
