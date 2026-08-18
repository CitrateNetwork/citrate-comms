/**
 * Row-store writer (AGENTS_03). Parses a tabular file and persists it as structured
 * rows: batch → sheets → columns (profile) → rows. Sensitive cells (email/phone/
 * address) are encrypted into `cellsEnc` and kept OUT of the queryable `cells` jsonb;
 * a per-row blind index over the first email column feeds cross-record dedupe.
 */
import { eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { importBatches, importSheets, importColumns, importRows } from "@/lib/db/schema";
import { encryptField, blindIndex } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { parseWorkbook, type ParsedSheet, type ParsedWorkbook } from "./import-parse";

const ROW_INSERT_CHUNK = 200;

export interface IngestTableArgs {
  workspaceId: string;
  documentId?: string | null;
  filename: string;
  mime: string | null;
  buffer: Buffer;
  bySub: string;
  /** Pre-parsed workbook (avoids a second parse when the caller already parsed for a summary). */
  parsed?: ParsedWorkbook;
}

export interface IngestTableResult {
  batchId: string;
  sheets: { id: string; name: string; rowCount: number; colCount: number }[];
}

function splitCells(sheet: ParsedSheet, row: Record<string, string>) {
  const sensitiveNames = new Set(sheet.columns.filter((c) => c.sensitive).map((c) => c.name));
  const cells: Record<string, string> = {};
  const sensitive: Record<string, string> = {};
  for (const [k, v] of Object.entries(row)) {
    if (v === "") continue;
    if (sensitiveNames.has(k)) sensitive[k] = v;
    else cells[k] = v;
  }
  return { cells, sensitive };
}

/** Parse + persist a tabular file into the row store. Never throws on a single bad
 *  sheet — it records what it can and marks the batch ready. */
export async function ingestTable(args: IngestTableArgs): Promise<IngestTableResult> {
  const parsed = args.parsed ?? (await parseWorkbook(args.buffer, args.filename));

  const [batch] = await db()
    .insert(importBatches)
    .values({
      workspaceId: args.workspaceId,
      documentId: args.documentId ?? null,
      filename: args.filename,
      mime: args.mime,
      status: "parsing",
      sheetCount: parsed.sheets.length,
      createdBySub: args.bySub,
    })
    .returning({ id: importBatches.id });
  const batchId = batch!.id;

  const out: IngestTableResult["sheets"] = [];
  for (const sheet of parsed.sheets) {
    const [sh] = await db()
      .insert(importSheets)
      .values({
        workspaceId: args.workspaceId,
        batchId,
        name: sheet.name,
        ord: sheet.ord,
        headerRow: sheet.headerRow,
        rowCount: sheet.rows.length,
        colCount: sheet.columns.length,
      })
      .returning({ id: importSheets.id });
    const sheetId = sh!.id;

    if (sheet.columns.length > 0) {
      await db().insert(importColumns).values(
        sheet.columns.map((c) => ({
          workspaceId: args.workspaceId,
          sheetId,
          ord: sheet.columns.indexOf(c),
          name: c.name,
          type: c.type,
          sensitive: c.sensitive,
          nullFrac: c.nullFrac,
          sampleJson: c.samples,
        })),
      );
    }

    // The first email column drives the row's dedupe blind index.
    const emailCol = sheet.columns.find((c) => c.type === "email")?.name ?? null;

    const rowValues = sheet.rows.map((row, i) => {
      const { cells, sensitive } = splitCells(sheet, row);
      const emailVal = emailCol ? row[emailCol]?.trim().toLowerCase() : "";
      return {
        workspaceId: args.workspaceId,
        sheetId,
        rowIndex: i,
        cells,
        cellsEnc: Object.keys(sensitive).length ? encryptField(args.workspaceId, JSON.stringify(sensitive)) : null,
        dedupeKey: emailVal ? blindIndex(args.workspaceId, "email", emailVal) : null,
        status: "new" as const,
      };
    });
    for (let i = 0; i < rowValues.length; i += ROW_INSERT_CHUNK) {
      await db().insert(importRows).values(rowValues.slice(i, i + ROW_INSERT_CHUNK));
    }

    out.push({ id: sheetId, name: sheet.name, rowCount: sheet.rows.length, colCount: sheet.columns.length });
  }

  await db().update(importBatches).set({ status: "ready" }).where(eq(importBatches.id, batchId));
  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.bySub, event: "table_ingested", target: batchId });
  return { batchId, sheets: out };
}
