/**
 * Apply Drizzle migrations to the Neon database named by DATABASE_URL.
 * Generate migrations first with `pnpm db:generate`.
 */
import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { migrate } from "drizzle-orm/neon-http/migrator";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const dbc = drizzle(neon(url));
await migrate(dbc, { migrationsFolder: "./src/lib/db/migrations" });
console.log("migrations applied");
