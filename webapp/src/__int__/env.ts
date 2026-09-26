/**
 * Per-file env for integration tests: mock auth (the `x-citrate-dev-address` header
 * becomes sub `dev:<addr>`), a fixed test encryption key, and the throwaway database.
 * Runs before any test module is imported.
 */
process.env.NEXT_PUBLIC_AUTH_MODE = "mock";
process.env.COMMS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
if (process.env.TEST_DATABASE_URL) process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;

// Attachment stores for the blob tests (ATT-HARDEN): a PRIVATE primary store and a LEGACY
// public store, recognized by host. Fixture tokens only — the network SDK is stubbed in the
// files that exercise the signed/stream paths, so these are used purely for host derivation.
// (private host: privstore.private.…; legacy public host: pubstore.public.…)
process.env.BLOB_READ_WRITE_TOKEN = ["vercel_blob_rw", "privstore", "testfixture"].join("_");
process.env.BLOB_LEGACY_READ_WRITE_TOKEN = ["vercel_blob_rw", "pubstore", "testfixture"].join("_");
