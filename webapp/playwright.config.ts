import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  retries: 0,
  use: { baseURL: process.env.APP_ORIGIN || "http://localhost:3004" },
  webServer: {
    command: "pnpm dev",
    url: process.env.APP_ORIGIN || "http://localhost:3004",
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
