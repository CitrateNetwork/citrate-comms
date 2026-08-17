/**
 * Read side of the row store (AGENTS_03). Every function is BOUNDED so an agent can
 * profile / window / aggregate a 100k-cell table without ever pulling it into context:
 *  - listTables:  datasets + sheets + recent import jobs
 *  - getSheetSchema: columns + types + a few sample values (never rows)
 *  - readRows:    a ≤50-row window (sensitive cells masked unless reveal=true)
 *  - queryTable:  count / distinct / group-by run in SQL over the jsonb cells
 */
import { and, desc, eq, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { importBatches, importSheets, importColumns, importRows, importJobs } from "@/lib/db/schema";
import { decryptField } from "@/lib/security/crypto";

export const READ_MAX = 50;

export interface SheetMeta {
  id: string;
  name: string;
  rowCount: number;
  colCount: number;
}
export interface TableBatch {
  batchId: string;
  filename: string;
  status: string;
  createdAt: string;
  sheets: SheetMeta[];
}
export interface ImportJobBrief {
  id: string;
  sheetId: string;
  status: string;
  cursor: number;
  total: number;
  created: number;
  updated: number;
  held: number;
  failed: number;
}

export async function listTables(workspaceId: string, limit = 50): Promise<{ batches: TableBatch[]; jobs: ImportJobBrief[] }> {
  const batches = await db()
    .select({ id: importBatches.id, filename: importBatches.filename, status: importBatches.status, createdAt: importBatches.createdAt })
    .from(importBatches)
    .where(eq(importBatches.workspaceId, workspaceId))
    .orderBy(desc(importBatches.createdAt))
    .limit(Math.min(Math.max(limit, 1), 50));

  const sheets = batches.length
    ? await db()
        .select({ id: importSheets.id, batchId: importSheets.batchId, name: importSheets.name, rowCount: importSheets.rowCount, colCount: importSheets.colCount, ord: importSheets.ord })
        .from(importSheets)
        .where(eq(importSheets.workspaceId, workspaceId))
        .orderBy(importSheets.ord)
    : [];
  const byBatch = new Map<string, SheetMeta[]>();
  for (const s of sheets) {
    if (!byBatch.has(s.batchId)) byBatch.set(s.batchId, []);
    byBatch.get(s.batchId)!.push({ id: s.id, name: s.name, rowCount: s.rowCount, colCount: s.colCount });
  }

  const jobs = await db()
    .select()
    .from(importJobs)
    .where(eq(importJobs.workspaceId, workspaceId))
    .orderBy(desc(importJobs.createdAt))
    .limit(20);

  return {
    batches: batches.map((b) => ({
      batchId: b.id,
      filename: b.filename,
      status: b.status,
      createdAt: b.createdAt.toISOString(),
      sheets: byBatch.get(b.id) ?? [],
    })),
    jobs: jobs.map((j) => ({
      id: j.id,
      sheetId: j.sheetId,
      status: j.status,
      cursor: j.cursor,
      total: j.total,
      created: j.createdCount,
      updated: j.updatedCount,
      held: j.heldCount,
      failed: j.failedCount,
    })),
  };
}

export interface ColumnProfile {
  name: string;
  type: string;
  sensitive: boolean;
  nullFrac: number;
  samples: string[];
}

async function sheetColumns(workspaceId: string, sheetId: string): Promise<ColumnProfile[]> {
  const cols = await db()
    .select()
    .from(importColumns)
    .where(and(eq(importColumns.workspaceId, workspaceId), eq(importColumns.sheetId, sheetId)))
    .orderBy(importColumns.ord);
  return cols.map((c) => ({
    name: c.name,
    type: c.type,
    sensitive: c.sensitive,
    nullFrac: c.nullFrac,
    samples: Array.isArray(c.sampleJson) ? (c.sampleJson as string[]) : [],
  }));
}

export async function getSheetSchema(
  workspaceId: string,
  sheetId: string,
): Promise<{ sheet: SheetMeta & { batchId: string; filename: string }; columns: ColumnProfile[] } | null> {
  const [sh] = await db()
    .select({ id: importSheets.id, name: importSheets.name, rowCount: importSheets.rowCount, colCount: importSheets.colCount, batchId: importSheets.batchId, filename: importBatches.filename })
    .from(importSheets)
    .innerJoin(importBatches, eq(importSheets.batchId, importBatches.id))
    .where(and(eq(importSheets.workspaceId, workspaceId), eq(importSheets.id, sheetId)))
    .limit(1);
  if (!sh) return null;
  return { sheet: { id: sh.id, name: sh.name, rowCount: sh.rowCount, colCount: sh.colCount, batchId: sh.batchId, filename: sh.filename }, columns: await sheetColumns(workspaceId, sheetId) };
}

function maskValue(name: string, type: string, v: string): string {
  if (!v) return v;
  if (type === "email") {
    const [u, d] = v.split("@");
    return d ? `${(u ?? "").slice(0, 1)}•••@${d}` : "•••";
  }
  if (type === "phone") return `•••${v.replace(/\D/g, "").slice(-4)}`;
  return v.length <= 2 ? "•••" : `${v.slice(0, 1)}•••`;
}

export interface ReadRowsOpts {
  offset?: number;
  limit?: number;
  columns?: string[];
  filter?: { column: string; op: "eq" | "contains"; value: string };
  revealSensitive?: boolean;
}

export async function readRows(
  workspaceId: string,
  sheetId: string,
  opts: ReadRowsOpts = {},
): Promise<{ total: number; offset: number; limit: number; columns: string[]; rows: Record<string, string>[] }> {
  const cols = await sheetColumns(workspaceId, sheetId);
  const sensitive = new Set(cols.filter((c) => c.sensitive).map((c) => c.name));
  const typeByName = new Map(cols.map((c) => [c.name, c.type]));
  const limit = Math.min(Math.max(opts.limit ?? 20, 1), READ_MAX);
  const offset = Math.max(opts.offset ?? 0, 0);

  const base = and(eq(importRows.workspaceId, workspaceId), eq(importRows.sheetId, sheetId));
  // Non-sensitive filter can run in SQL; a sensitive filter is refused (masked data).
  let where = base;
  const f = opts.filter;
  if (f && !sensitive.has(f.column)) {
    const frag = f.op === "contains"
      ? sql`(${importRows.cells} ->> ${f.column}) ILIKE ${"%" + f.value + "%"}`
      : sql`(${importRows.cells} ->> ${f.column}) = ${f.value}`;
    where = and(base, frag)!;
  }

  const [{ n } = { n: 0 }] = await db().select({ n: sql<number>`count(*)::int` }).from(importRows).where(where);
  const rows = await db()
    .select({ cells: importRows.cells, cellsEnc: importRows.cellsEnc })
    .from(importRows)
    .where(where)
    .orderBy(importRows.rowIndex)
    .offset(offset)
    .limit(limit);

  const wanted = opts.columns && opts.columns.length ? opts.columns : cols.map((c) => c.name);
  const out = rows.map((r) => {
    const merged: Record<string, string> = { ...(r.cells as Record<string, string>) };
    if (r.cellsEnc) {
      try {
        const dec = JSON.parse(decryptField(workspaceId, r.cellsEnc)) as Record<string, string>;
        for (const [k, v] of Object.entries(dec)) {
          merged[k] = opts.revealSensitive ? v : maskValue(k, typeByName.get(k) ?? "text", v);
        }
      } catch {
        /* skip unreadable */
      }
    }
    const picked: Record<string, string> = {};
    for (const c of wanted) if (merged[c] !== undefined) picked[c] = merged[c]!;
    return picked;
  });

  return { total: Number(n) || 0, offset, limit, columns: wanted, rows: out };
}

export type QueryOp = "count" | "distinct" | "groupby";

export async function queryTable(
  workspaceId: string,
  sheetId: string,
  q: { op: QueryOp; column?: string; where?: { column: string; op: "eq" | "contains"; value: string } },
): Promise<{ op: QueryOp; count?: number; groups?: { value: string; count: number }[]; error?: string }> {
  const cols = await sheetColumns(workspaceId, sheetId);
  const sensitive = new Set(cols.filter((c) => c.sensitive).map((c) => c.name));

  const base = and(eq(importRows.workspaceId, workspaceId), eq(importRows.sheetId, sheetId));
  let where = base;
  if (q.where && !sensitive.has(q.where.column)) {
    const frag = q.where.op === "contains"
      ? sql`(${importRows.cells} ->> ${q.where.column}) ILIKE ${"%" + q.where.value + "%"}`
      : sql`(${importRows.cells} ->> ${q.where.column}) = ${q.where.value}`;
    where = and(base, frag)!;
  }

  if (q.op === "count") {
    const [{ n } = { n: 0 }] = await db().select({ n: sql<number>`count(*)::int` }).from(importRows).where(where);
    return { op: "count", count: Number(n) || 0 };
  }

  if (!q.column) return { op: q.op, error: "column required for distinct/groupby" };
  if (sensitive.has(q.column)) return { op: q.op, error: `cannot aggregate sensitive column "${q.column}"` };

  const groups = await db()
    .select({ value: sql<string>`coalesce(${importRows.cells} ->> ${q.column}, '∅')`, count: sql<number>`count(*)::int` })
    .from(importRows)
    .where(where)
    .groupBy(sql`${importRows.cells} ->> ${q.column}`)
    .orderBy(desc(sql`count(*)`))
    .limit(q.op === "distinct" ? 200 : 50);

  return { op: q.op, groups: groups.map((g) => ({ value: g.value, count: Number(g.count) || 0 })) };
}
