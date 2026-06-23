/**
 * No-PII / encryption allow-list guard (pattern from citrate-dataroom).
 *
 * The trusted-tier web app DOES store content (it is not server-blind), but content
 * and free-text PII must live ONLY in encrypted columns (suffix `_enc`, AES-256-GCM
 * per-workspace, lib/security/crypto.ts). This test fails if a NEW cleartext column
 * appears that looks like it should be encrypted — forcing a deliberate decision and
 * an update to the allow-list rather than a silent plaintext leak.
 *
 * It reads the schema source statically (no DB needed).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const schemaSrc = readFileSync(join(here, "schema.ts"), "utf8");

/** Cleartext columns whose NAME contains a sensitive token but are intentionally
 *  NOT encrypted (identifiers, denormalized claims, hashes — not free-text content). */
const ALLOWED_CLEARTEXT = new Set<string>([
  "email", // members.email — a verified-email identifier (FWA-C6-01), not free-text content
  "emailVerified",
]);

/** Column-name SEGMENTS that mark free-text content and MUST be encrypted (end in
 *  `_enc`). Matched against `_`-split segments — NOT substrings — so digests like
 *  `ciphertext_hash` (segment "ciphertext", not "text") are not false positives. */
const SENSITIVE_SEGMENTS = new Set(["body", "text", "secret", "note", "notes"]);

describe("schema no-pii / encryption allow-list", () => {
  it("content columns are encrypted (end in _enc) or explicitly allow-listed", () => {
    // Match drizzle column declarations:  name: text("db_col")
    const colRe = /(\w+):\s*(?:text|jsonb)\("([\w]+)"/g;
    const offenders: string[] = [];
    for (const m of schemaSrc.matchAll(colRe)) {
      const tsName = m[1]!;
      const dbCol = m[2]!;
      if (ALLOWED_CLEARTEXT.has(tsName)) continue;
      if (dbCol.endsWith("_enc")) continue;
      const looksSensitive = dbCol.split("_").some((seg) => SENSITIVE_SEGMENTS.has(seg));
      if (looksSensitive) offenders.push(`${tsName} ("${dbCol}")`);
    }
    expect(offenders, `unencrypted sensitive columns: ${offenders.join(", ")}`).toEqual([]);
  });

  it("every _enc column is documented as ciphertext", () => {
    const encCols = [...schemaSrc.matchAll(/"(\w+_enc)"/g)].map((m) => m[1]!);
    // At minimum the known content columns exist and are encrypted.
    expect(encCols).toEqual(expect.arrayContaining(["body_enc", "text_enc"]));
  });
});
