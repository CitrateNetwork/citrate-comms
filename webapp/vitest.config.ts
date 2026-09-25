import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Real-Postgres integration tests run via `pnpm test:int` (vitest.int.config.ts).
    exclude: ["src/**/*.int.test.ts", "node_modules/**"],
    coverage: { provider: "v8", include: ["src/lib/**"] },
  },
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
});
