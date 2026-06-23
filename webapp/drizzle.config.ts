import { defineConfig } from "drizzle-kit";

/**
 * Drizzle Kit config for the citrate-comms web app schema. `drizzle-kit generate`
 * reads the schema and emits SQL into src/lib/db/migrations/ — no live DB required.
 * Applying (scripts/db-migrate.mjs) reads DATABASE_URL.
 *
 * Every domain table is tenant-scoped by `workspace_id`. Content columns ending in
 * `_enc` hold AES-256-GCM ciphertext (per-workspace key); see lib/security/crypto.ts
 * and the no-pii allow-list test.
 */
export default defineConfig({
  schema: "./src/lib/db/schema.ts",
  out: "./src/lib/db/migrations",
  dialect: "postgresql",
  dbCredentials: { url: process.env.DATABASE_URL ?? "" },
  strict: true,
  verbose: true,
});
