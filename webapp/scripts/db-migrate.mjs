/**
 * Apply Drizzle migrations to the Postgres database. Uses a DIRECT (non-pooler)
 * connection — DDL/migrations need session mode, not the transaction pooler. Prefers
 * DATABASE_URL_UNPOOLED (the DO primary, port 25060), falling back to DATABASE_URL.
 * Generate migrations first with `pnpm db:generate`.
 */
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

const url = process.env.DATABASE_URL_UNPOOLED || process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL(_UNPOOLED) is not set");
  process.exit(1);
}

const sql = postgres(url, { max: 1, prepare: false, idle_timeout: 10, connect_timeout: 20 });
const dbc = drizzle(sql);
await migrate(dbc, { migrationsFolder: "./src/lib/db/migrations" });
console.log("migrations applied");
await sql.end();
