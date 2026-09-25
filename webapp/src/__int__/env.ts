/**
 * Per-file env for integration tests: mock auth (the `x-citrate-dev-address` header
 * becomes sub `dev:<addr>`), a fixed test encryption key, and the throwaway database.
 * Runs before any test module is imported.
 */
process.env.NEXT_PUBLIC_AUTH_MODE = "mock";
process.env.COMMS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
if (process.env.TEST_DATABASE_URL) process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
