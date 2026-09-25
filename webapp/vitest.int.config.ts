import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

/**
 * Integration tests (PBA-R2): real route handlers against a real Postgres with every
 * migration applied. `pnpm test:int` with TEST_DATABASE_URL pointing at a throwaway DB.
 * Files run serially because they share one database.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.int.test.ts"],
    globalSetup: ["src/__int__/global-setup.ts"],
    setupFiles: ["src/__int__/env.ts"],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
});
