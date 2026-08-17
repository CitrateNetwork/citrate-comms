/**
 * Tabular parser for the structured-ingest subsystem (AGENTS_03).
 *
 * Pure (no DB): buffer → normalized sheets/columns/rows with per-column TYPE
 * INFERENCE and SENSITIVITY detection. xlsx/xls via SheetJS; csv/tsv via SheetJS's
 * codepage-aware reader; pdf tables are handled upstream (extract → csv-ish text →
 * here). Every cell is normalized to a trimmed string; the inferred `type` is
 * metadata the import engine uses when it maps a column onto a CRM field.
 *
 * Sensitive columns (email/phone/personal address) are flagged so the store can
 * encrypt them and keep them out of the queryable jsonb + samples.
 */

export type ColType =
  | "text" | "number" | "currency" | "date" | "email" | "phone" | "url" | "boolean" | "select";

export interface ParsedColumn {
  name: string;
  type: ColType;
  sensitive: boolean;
  /** percent of rows where this column is empty (0..100) */
  nullFrac: number;
  /** a few example values — EMPTY for sensitive columns (never sampled) */
  samples: string[];
}

export interface ParsedSheet {
  name: string;
  ord: number;
  headerRow: number;
  columns: ParsedColumn[];
  /** row cells keyed by (de-duplicated) column name; values are trimmed strings */
  rows: Record<string, string>[];
}

export interface ParsedWorkbook {
  sheets: ParsedSheet[];
}

// Guardrails so a hostile/huge file can't exhaust memory.
export const MAX_SHEETS = 40;
export const MAX_COLS = 512;
export const MAX_ROWS = 200_000;
const INFER_SAMPLE = 300; // rows scanned for type inference
const SAMPLE_KEEP = 5;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// Matches full URLs, www.*, and bare domains ("acme.com", "sub.acme.io") — but not
// emails (no '@') and not plain words (needs a dotted TLD-like tail).
const URL_RE = /^(https?:\/\/|www\.)\S+$|^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)+(\/\S*)?$/i;
const PHONE_RE = /^[+(]?[\d][\d\s().-]{6,}\d$/;
const NUM_RE = /^-?\$?[\d,]+(\.\d+)?%?$/;
const CURRENCY_RE = /^[$€£¥]\s?-?[\d,]+(\.\d+)?$/;
const BOOL_RE = /^(true|false|yes|no|y|n)$/i;
const DATE_RE = /^(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}\/\d{1,2}\/\d{2,4})(\s.*)?$/;

const SENSITIVE_NAME_RE = /\b(e[-\s]?mail|phone|mobile|cell|fax|street|address|addr|zip|postal[\s-]?code|ssn|social security|dob|date of birth|birth|passport|tax id|national id)\b/i;
// Names that look like an address WORD but are safe to keep queryable (coarse geo).
const COARSE_GEO_RE = /\b(city|state|province|region|country)\b/i;

function norm(v: unknown): string {
  if (v == null) return "";
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v).replace(/\s+/g, " ").trim();
}

const PHONE_NAME_RE = /\b(phone|mobile|cell|fax|tel)\b/i;

function looksLikePhone(v: string, nameHint: boolean): boolean {
  if (!PHONE_RE.test(v)) return false;
  const digits = v.replace(/\D/g, "").length;
  if (digits < 7 || digits > 15) return false;
  // A phone number is formatted (separators/leading +) OR the COLUMN name says phone.
  return /[\s().+-]/.test(v) || nameHint;
}

function classify(name: string, values: string[]): ColType {
  const nonEmpty = values.filter((v) => v !== "");
  if (nonEmpty.length === 0) return "text";
  const frac = (pred: (v: string) => boolean) => nonEmpty.filter(pred).length / nonEmpty.length;
  if (frac((v) => EMAIL_RE.test(v)) > 0.7) return "email";
  if (frac((v) => URL_RE.test(v)) > 0.7) return "url";
  if (frac((v) => CURRENCY_RE.test(v)) > 0.6) return "currency";
  // Date BEFORE phone — "2026-08-14" also satisfies the loose phone shape.
  if (frac((v) => DATE_RE.test(v)) > 0.7) return "date";
  if (frac((v) => looksLikePhone(v, PHONE_NAME_RE.test(name))) > 0.7) return "phone";
  if (frac((v) => BOOL_RE.test(v)) > 0.9) return "boolean";
  if (frac((v) => NUM_RE.test(v)) > 0.85) return "number";
  const distinct = new Set(nonEmpty.map((v) => v.toLowerCase()));
  if (distinct.size >= 2 && distinct.size <= 12 && nonEmpty.length >= distinct.size * 3) return "select";
  return "text";
}

function isSensitive(name: string, type: ColType): boolean {
  if (type === "email" || type === "phone") return true;
  // A domain (e.g. "Email Domain" = acme.com) is not personal data.
  if (/\bdomain\b/i.test(name)) return false;
  if (COARSE_GEO_RE.test(name)) return false;
  return SENSITIVE_NAME_RE.test(name);
}

/** Choose the header row: the first of the first 6 rows whose filled-cell count is
 *  close to the widest row (skips single-cell title banners common in report sheets). */
function detectHeaderRow(matrix: unknown[][]): number {
  const scan = matrix.slice(0, 6);
  const widths = scan.map((r) => r.filter((c) => norm(c) !== "").length);
  const maxW = Math.max(1, ...widths);
  for (let i = 0; i < widths.length; i++) {
    if (widths[i]! >= Math.max(2, Math.floor(maxW * 0.5))) return i;
  }
  return 0;
}

function dedupeHeaders(raw: string[]): string[] {
  const seen = new Map<string, number>();
  return raw.map((h, i) => {
    let name = norm(h) || `col_${i + 1}`;
    if (seen.has(name)) {
      const n = seen.get(name)! + 1;
      seen.set(name, n);
      name = `${name} (${n})`;
    } else {
      seen.set(name, 1);
    }
    return name;
  });
}

/** Parse a workbook buffer into normalized sheets. `raw` array-of-arrays comes from
 *  SheetJS with `header:1` so we control header-row detection ourselves. */
export async function parseWorkbook(buf: Buffer, _filename?: string): Promise<ParsedWorkbook> {
  const XLSX = await import("xlsx");
  const wb = XLSX.read(buf, { type: "buffer", cellDates: true, raw: false });
  const sheets: ParsedSheet[] = [];

  for (const [ord, sheetName] of wb.SheetNames.slice(0, MAX_SHEETS).entries()) {
    const ws = wb.Sheets[sheetName];
    if (!ws) continue;
    const matrix = XLSX.utils.sheet_to_json<unknown[]>(ws, { header: 1, defval: "", blankrows: false, raw: false });
    if (matrix.length === 0) {
      sheets.push({ name: sheetName || `Sheet ${ord + 1}`, ord, headerRow: 0, columns: [], rows: [] });
      continue;
    }
    const headerRow = detectHeaderRow(matrix);
    const headers = dedupeHeaders((matrix[headerRow] ?? []).slice(0, MAX_COLS).map(norm));
    const bodyRows = matrix.slice(headerRow + 1, headerRow + 1 + MAX_ROWS);

    const rows: Record<string, string>[] = bodyRows
      .map((r) => {
        const obj: Record<string, string> = {};
        for (let c = 0; c < headers.length; c++) obj[headers[c]!] = norm(r[c]);
        return obj;
      })
      .filter((obj) => Object.values(obj).some((v) => v !== "")); // drop fully-empty rows

    const columns: ParsedColumn[] = headers.map((name) => {
      const colVals = rows.map((r) => r[name] ?? "");
      const sample = colVals.slice(0, INFER_SAMPLE);
      const type = classify(name, sample);
      const sensitive = isSensitive(name, type);
      const nulls = colVals.filter((v) => v === "").length;
      const nullFrac = rows.length ? Math.round((nulls / rows.length) * 100) : 0;
      const samples = sensitive
        ? []
        : [...new Set(colVals.filter((v) => v !== ""))].slice(0, SAMPLE_KEEP);
      return { name, type, sensitive, nullFrac, samples };
    });

    sheets.push({ name: sheetName || `Sheet ${ord + 1}`, ord, headerRow, columns, rows });
  }

  return { sheets };
}

/** A COMPACT, RAG-friendly summary of a parsed workbook — schema + a few sample rows,
 *  with sensitive columns masked. Indexed instead of the full-cell dump, so a big
 *  table no longer blows the chunk cap while `documents.read` still answers
 *  "what's in this file?". The structured rows live in the row store. */
export function summarizeParsed(parsed: ParsedWorkbook, maxSampleRows = 4): string {
  const parts: string[] = [];
  for (const s of parsed.sheets) {
    parts.push(`# ${s.name} (${s.rows.length} rows × ${s.columns.length} columns)`);
    if (s.columns.length) {
      parts.push("Columns: " + s.columns.map((c) => `${c.name} [${c.type}${c.sensitive ? ", sensitive" : ""}]`).join(", "));
      const shown = s.columns.filter((c) => !c.sensitive).map((c) => c.name);
      if (shown.length) {
        parts.push("Sample rows:");
        parts.push(shown.join(" | "));
        for (const r of s.rows.slice(0, maxSampleRows)) {
          parts.push(shown.map((c) => r[c] ?? "").join(" | "));
        }
      }
    }
    parts.push("");
  }
  return parts.join("\n");
}

/** True when a file should be parsed structurally (row store) rather than only RAG. */
export function isTabularFile(name: string, mime: string | null): boolean {
  const lower = name.toLowerCase();
  if (/\.(xlsx|xls|csv|tsv)$/.test(lower)) return true;
  if (mime === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") return true;
  if (mime === "application/vnd.ms-excel") return true;
  if ((mime === "text/csv" || mime === "text/tab-separated-values")) return true;
  return false;
}
