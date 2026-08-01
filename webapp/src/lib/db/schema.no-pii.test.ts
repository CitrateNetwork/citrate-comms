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
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WIDENED 2026-08-01 (QA sweep). Two defects in the guard itself:
 *
 *   1. IT COULD NOT SEE NAMES. `SENSITIVE_SEGMENTS` was {body, text, secret, note,
 *      notes}. A CRM's most identifying field is a person's NAME, and
 *      `contacts.name` sat in cleartext — directly beside `contacts.email_enc`,
 *      which IS encrypted — with no comment recording that as a choice. The guard
 *      exists to force "a deliberate decision ... rather than a silent plaintext
 *      leak", and a contact's name slipped through in silence because the segment
 *      list never anticipated that shape. Also missed: job titles, channel topics,
 *      company domains, and display names.
 *
 *   2. THE ALLOW-LIST KEY WAS NOT UNIQUE. It matched the TypeScript property name,
 *      so a single `"email"` entry blessed `members.email`, `invites.email`, and
 *      every future `X.email`. An exemption granted to one table silently applied
 *      to all of them. Entries are now `table.column`.
 *
 * The widened guard does NOT assert that these columns must be encrypted — several
 * genuinely cannot be, because a trusted-tier app has to list and search them. It
 * asserts that each one is a RECORDED decision. That is the difference between a
 * trade-off and an oversight.
 * ─────────────────────────────────────────────────────────────────────────────
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const schemaSrc = readFileSync(join(here, "schema.ts"), "utf8");

/**
 * Cleartext columns that are a DELIBERATE trade-off, keyed `table.column`, each with
 * the reason it is not encrypted. Adding a row here is the decision the guard exists
 * to force; it should be uncomfortable, not routine.
 */
const ALLOWED_CLEARTEXT: Record<string, string> = {
  // Identifiers and routing keys — not free-text content.
  "members.email": "verified-email IDENTIFIER (FWA-C6-01), matched on at login; not free text",
  "members.wallet_address": "a public chain address, denormalized from the OIDC claim",
  "invites.email": "the invite is ADDRESSED to it; encrypting it would make delivery impossible",
  "email_suppression.email":
    "a suppression list is USELESS unless it can be matched against an outbound address",
  "devices.label": "a device nickname the member types for their own recognition ('MacBook')",

  // Structural names a trusted-tier app must list, sort and search server-side.
  // Encrypting these would break the product, not harden it — they are named here so
  // that is a stated trade-off rather than an assumption.
  "workspaces.name": "workspace names are listed and routed on server-side; not personal data",
  "channels.name": "channel list + routing; visible to every member of the workspace anyway",
  "accounts.name": "company name — a business identifier, sorted and searched server-side",
  "accounts.domain": "company domain — a public business identifier used for matching",
  "deals.name": "pipeline board is sorted/filtered server-side",
  "projects.name": "project list is sorted/filtered server-side",
  "boards.name": "board list is sorted server-side",
  "board_columns.name": "board column headers ('To do'); product vocabulary, not user content",
  "agents.name": "an agent's handle, shown to every workspace member by design",
  "agent_personas.name": "a persona's handle, shown to every workspace member by design",
  "crm_field_defs.label": "a custom-field NAME (schema config), not the value stored in it",
  "crm_tags.label": "tag vocabulary, filtered server-side",
  "crm_views.name": "a saved-view name the member chose for their own navigation",

  // ── FLAGGED FOR AN OWNER DECISION (QA 2026-08-01) ──────────────────────────
  // Recorded so the suite is green and the state is VISIBLE, not because the
  // trade-off has been agreed. Each is personal data or free text in a product that
  // encrypts message bodies beside it. See docs/QA_2026-08-01_COMMS.md.
  "members.display_name": "OWNER DECISION PENDING — a person's name, held in cleartext",
  "contacts.name":
    "OWNER DECISION PENDING — a contact's name is the CRM's most identifying field, and its email IS encrypted beside it",
  "contacts.title": "OWNER DECISION PENDING — job title; personal data under GDPR Art.4",
  "channels.topic": "OWNER DECISION PENDING — free text, unlike channels.name",
  "threads.title": "OWNER DECISION PENDING — free text, often the substance of the thread",
  "tasks.title": "OWNER DECISION PENDING — free text, often the substance of the task",
  "tasks.description": "OWNER DECISION PENDING — free text, beside encrypted message bodies",
  "agent_threads.title": "OWNER DECISION PENDING — free text summarising an agent conversation",
  "agent_resources.title": "OWNER DECISION PENDING — free text naming an attached resource",
  "documents.name":
    "OWNER DECISION PENDING — a filename frequently reveals its contents ('Q3-layoffs.xlsx')",
};

/**
 * Column-name SEGMENTS that mark free-text or personal data and must be encrypted
 * (end in `_enc`) or allow-listed. Matched against `_`-split segments — NOT
 * substrings — so digests like `ciphertext_hash` (segment "ciphertext", not "text")
 * are not false positives.
 */
const SENSITIVE_SEGMENTS = new Set([
  // free-text content
  "body",
  "text",
  "note",
  "notes",
  "topic",
  "description",
  "secret",
  // personal / identifying data
  "name",
  "title",
  "label",
  "email",
  "phone",
  "address",
  "domain",
]);

/** Every `table.column` declared in the schema, with its TS property name. */
function columns(): { table: string; col: string; ts: string }[] {
  const out: { table: string; col: string; ts: string }[] = [];
  // `export const contacts = pgTable(\n  "contacts",\n  { ... }`
  const tableRe = /pgTable\(\s*"(\w+)"\s*,\s*\{/g;
  let t: RegExpExecArray | null;
  while ((t = tableRe.exec(schemaSrc))) {
    const table = t[1]!;
    // Scan forward to the matching close brace of this table's column object.
    const start = t.index + t[0].length;
    let depth = 1;
    let i = start;
    for (; i < schemaSrc.length && depth > 0; i++) {
      if (schemaSrc[i] === "{") depth++;
      else if (schemaSrc[i] === "}") depth--;
    }
    const block = schemaSrc.slice(start, i);
    const colRe = /(\w+):\s*(?:text|jsonb|varchar)\("([\w]+)"/g;
    let c: RegExpExecArray | null;
    while ((c = colRe.exec(block))) out.push({ table, ts: c[1]!, col: c[2]! });
  }
  return out;
}

describe("schema no-pii / encryption allow-list", () => {
  it("parses the schema into table-qualified columns (the guard can see what it judges)", () => {
    const cols = columns();
    expect(cols.length, "no columns parsed — the guard would vacuously pass").toBeGreaterThan(20);
    // The regression that motivated table-keying: `name` exists on many tables, so a
    // property-name allow-list could never have exempted one without exempting all.
    const names = cols.filter((c) => c.col === "name").map((c) => c.table);
    expect(new Set(names).size, "several tables have a `name` column").toBeGreaterThan(3);
  });

  it("every sensitive column is encrypted or a RECORDED decision", () => {
    const offenders: string[] = [];
    for (const { table, col } of columns()) {
      if (col.endsWith("_enc")) continue;
      if (!col.split("_").some((seg) => SENSITIVE_SEGMENTS.has(seg))) continue;
      if (ALLOWED_CLEARTEXT[`${table}.${col}`]) continue;
      offenders.push(`${table}.${col}`);
    }
    expect(
      offenders,
      `cleartext sensitive columns with no recorded decision: ${offenders.join(", ")}. ` +
        `Encrypt them (suffix _enc) or add a table.column entry to ALLOWED_CLEARTEXT ` +
        `stating WHY — that entry IS the decision, and it is meant to be uncomfortable.`,
    ).toEqual([]);
  });

  it("every allow-list entry carries a non-trivial reason", () => {
    for (const [key, reason] of Object.entries(ALLOWED_CLEARTEXT)) {
      expect(reason.length, `${key} needs a real reason, not a placeholder`).toBeGreaterThan(20);
    }
  });

  it("every allow-list entry still exists in the schema (no stale exemptions)", () => {
    // A rotted exemption is worse than none: it reads as considered while guarding a
    // column that no longer exists, and hides the next one that takes its name.
    const present = new Set(columns().map((c) => `${c.table}.${c.col}`));
    const stale = Object.keys(ALLOWED_CLEARTEXT).filter((k) => !present.has(k));
    expect(stale, `allow-list entries for columns that no longer exist: ${stale.join(", ")}`).toEqual([]);
  });

  it("every _enc column is documented as ciphertext", () => {
    const encCols = [...schemaSrc.matchAll(/"(\w+_enc)"/g)].map((m) => m[1]!);
    // At minimum the known content columns exist and are encrypted.
    expect(encCols).toEqual(expect.arrayContaining(["body_enc", "text_enc"]));
  });
});
