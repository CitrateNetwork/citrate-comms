/**
 * Unstructured/JSON → CRM entity extraction (PLANSET 10 / UDI Phase 1).
 *
 * The "Read" layer for non-tabular sources. Free-form text (PDF body, meeting
 * notes, a pasted block) is turned into CRM entity records via the inference
 * gateway, each carrying a confidence ∈ [0,1]. Structured JSON is mapped
 * deterministically at confidence 1.0 (no model needed).
 *
 * ADR-UDI-02: extraction is just another ROW PRODUCER. `stageExtracted` writes
 * the records into the SAME `import_rows` store under a synthetic sheet with an
 * identity `MappingSpec`, so they flow through the SAME `import-engine` job —
 * one dedupe path, one audit path, one resumable executor, one confidence gate.
 *
 * ADR-UDI-04: fail-closed. A model error or malformed output yields ZERO records
 * (nothing is guessed into the CRM); the caller routes the miss to review.
 */
import { z } from "zod";
import { eq } from "drizzle-orm";
import { generateObject } from "ai";
import { db } from "@/lib/db/client";
import { importBatches, importSheets, importColumns, importRows } from "@/lib/db/schema";
import { encryptField, blindIndex } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { getInferenceModel, defaultModelId } from "@/lib/ai/provider";
import type { MappingColumn, MappingSpec, StdTarget } from "./import-map";

// ── extracted record shape ───────────────────────────────────────────────────

export interface ExtractedRecord {
  account?: { name?: string; domain?: string };
  contact?: { name?: string; title?: string; email?: string; phone?: string };
  deal?: { name?: string; value?: string };
  task?: { title?: string; priority?: string };
  note?: string;
  /** Model's self-reported confidence for this record, clamped to [0,1]. */
  confidence: number;
}

export interface ExtractionResult {
  records: ExtractedRecord[];
  source: "json" | "model";
  error?: string;
}

// Zod schema the model must satisfy. Kept flat + optional so a small local model
// can fill only the fields it is sure about.
const RecordSchema = z.object({
  account: z.object({ name: z.string().optional(), domain: z.string().optional() }).optional(),
  contact: z
    .object({ name: z.string().optional(), title: z.string().optional(), email: z.string().optional(), phone: z.string().optional() })
    .optional(),
  deal: z.object({ name: z.string().optional(), value: z.string().optional() }).optional(),
  task: z.object({ title: z.string().optional(), priority: z.string().optional() }).optional(),
  note: z.string().optional(),
  confidence: z.number().min(0).max(1),
});
const ExtractionSchema = z.object({ records: z.array(RecordSchema) });

/** The model-call seam — injectable so the pure pipeline is testable without a gateway. */
export type DoExtract = (text: string, hint?: string) => Promise<{ records: unknown[] }>;

const EXTRACT_INSTRUCTION =
  "You extract CRM records from the text. Return an array of records. For each, fill ONLY the " +
  "fields you can support directly from the text (company/account name + web domain, the key " +
  "contact's full name, job title, email, phone; any deal/opportunity name + value; any next " +
  "step as a task title; a short note). Set `confidence` in [0,1] to how sure you are the record " +
  "is correct and complete. Do not invent values — leave a field out if the text does not state it.";

async function realExtract(text: string, hint?: string): Promise<{ records: unknown[] }> {
  const model = getInferenceModel({ model: { gateway: defaultModelId() } });
  const { object } = await generateObject({
    model,
    schema: ExtractionSchema,
    system: EXTRACT_INSTRUCTION + (hint ? `\nContext: ${hint}` : ""),
    prompt: text.slice(0, 24_000), // bound the prompt; long docs are chunked upstream
  });
  return object;
}

// ── pure helpers (unit-tested) ───────────────────────────────────────────────

function clamp01(n: unknown): number {
  const x = typeof n === "number" && Number.isFinite(n) ? n : 0;
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

function trimOpt(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t ? t : undefined;
}

function isEmptyRecord(r: ExtractedRecord): boolean {
  return !r.account?.name && !r.account?.domain && !r.contact?.name && !r.contact?.email && !r.contact?.title && !r.contact?.phone && !r.deal?.name && !r.deal?.value && !r.task?.title && !r.note;
}

/** Normalize raw model/JSON records: clamp confidence, trim strings, drop empties. */
export function normalizeRecords(raw: unknown[]): ExtractedRecord[] {
  const out: ExtractedRecord[] = [];
  for (const r0 of Array.isArray(raw) ? raw : []) {
    const r = (r0 ?? {}) as Record<string, unknown>;
    const acc = (r.account ?? {}) as Record<string, unknown>;
    const con = (r.contact ?? {}) as Record<string, unknown>;
    const deal = (r.deal ?? {}) as Record<string, unknown>;
    const task = (r.task ?? {}) as Record<string, unknown>;
    const rec: ExtractedRecord = {
      account: { name: trimOpt(acc.name), domain: trimOpt(acc.domain) },
      contact: { name: trimOpt(con.name), title: trimOpt(con.title), email: trimOpt(con.email), phone: trimOpt(con.phone) },
      deal: { name: trimOpt(deal.name), value: trimOpt(deal.value) },
      task: { title: trimOpt(task.title), priority: trimOpt(task.priority) },
      note: trimOpt(r.note),
      confidence: clamp01(r.confidence),
    };
    if (!isEmptyRecord(rec)) out.push(rec);
  }
  return out;
}

const JSON_KEYS: Record<string, (r: ExtractedRecord, v: string) => void> = {
  company: (r, v) => (r.account!.name = v),
  account: (r, v) => (r.account!.name = v),
  organization: (r, v) => (r.account!.name = v),
  domain: (r, v) => (r.account!.domain = v),
  website: (r, v) => (r.account!.domain = v),
  name: (r, v) => (r.contact!.name = v),
  contact: (r, v) => (r.contact!.name = v),
  fullname: (r, v) => (r.contact!.name = v),
  title: (r, v) => (r.contact!.title = v),
  role: (r, v) => (r.contact!.title = v),
  email: (r, v) => (r.contact!.email = v),
  phone: (r, v) => (r.contact!.phone = v),
  deal: (r, v) => (r.deal!.name = v),
  opportunity: (r, v) => (r.deal!.name = v),
  value: (r, v) => (r.deal!.value = v),
  amount: (r, v) => (r.deal!.value = v),
  budget: (r, v) => (r.deal!.value = v),
  task: (r, v) => (r.task!.title = v),
  nextstep: (r, v) => (r.task!.title = v),
  note: (r, v) => (r.note = v),
  notes: (r, v) => (r.note = v),
};

/** Deterministic JSON → records: object or {records:[...]} or bare array. Known keys
 *  only, confidence 1.0 (a structured source is trusted). Returns null if not JSON. */
export function structuredFromJson(text: string): ExtractedRecord[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const arr = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as { records?: unknown[] }).records)
      ? (parsed as { records: unknown[] }).records
      : parsed && typeof parsed === "object"
        ? [parsed]
        : null;
  if (!arr) return null;
  const out: ExtractedRecord[] = [];
  for (const item of arr) {
    if (!item || typeof item !== "object") continue;
    const rec: ExtractedRecord = { account: {}, contact: {}, deal: {}, task: {}, confidence: 1 };
    for (const [k, v] of Object.entries(item as Record<string, unknown>)) {
      if (typeof v !== "string" && typeof v !== "number") continue;
      const fn = JSON_KEYS[k.toLowerCase().replace(/[^a-z]/g, "")];
      if (fn) fn(rec, String(v).trim());
    }
    if (!isEmptyRecord(rec)) out.push(rec);
  }
  return out.length ? out : null;
}

// ── the extraction entry point ───────────────────────────────────────────────

/** Extract CRM records from text: deterministic JSON fast-path, else the model.
 *  Fail-closed — a model error returns zero records with an `error`. */
export async function extractEntities(text: string, opts?: { hint?: string; doExtract?: DoExtract }): Promise<ExtractionResult> {
  const json = structuredFromJson(text);
  if (json) return { records: json, source: "json" };
  const doExtract = opts?.doExtract ?? realExtract;
  try {
    const raw = await doExtract(text, opts?.hint);
    return { records: normalizeRecords(raw.records ?? []), source: "model" };
  } catch (e) {
    return { records: [], source: "model", error: e instanceof Error ? e.message : "extraction failed" };
  }
}

// ── staging: records → import_rows (identity mapping) ────────────────────────

// Canonical column names = the mapping std-target names, so the mapping is identity.
const SENSITIVE_COLS = new Set(["contact.email", "contact.phone"]);

/** Flatten one record to its canonical column→value cells. */
export function recordToCells(r: ExtractedRecord): Record<string, string> {
  const c: Record<string, string> = {};
  const put = (k: string, v?: string) => { if (v) c[k] = v; };
  put("account.name", r.account?.name);
  put("account.domain", r.account?.domain);
  put("contact.name", r.contact?.name);
  put("contact.title", r.contact?.title);
  put("contact.email", r.contact?.email);
  put("contact.phone", r.contact?.phone);
  put("deal.name", r.deal?.name);
  put("deal.value", r.deal?.value);
  put("task.title", r.task?.title);
  put("task.priority", r.task?.priority);
  put("note", r.note);
  return c;
}

/** The identity MappingSpec for staged extraction columns. `note` becomes a
 *  contact long-text custom field (resolveRow has no first-class note path yet). */
export function extractionMapping(): MappingSpec {
  const stdTargets: StdTarget[] = [
    "account.name", "account.domain", "contact.name", "contact.title", "contact.email", "contact.phone", "deal.name", "deal.value", "task.title", "task.priority",
  ];
  const stds: MappingColumn[] = stdTargets.map((t) => ({ column: t, map: { kind: "std", target: t } }));
  const note: MappingColumn = { column: "note", map: { kind: "custom", entity: "contact", key: "note", label: "Note", type: "longtext" } };
  return { primaryEntity: "contact", columns: [...stds, note], dedupe: { account: "domain", contact: "email" } };
}

export interface StageExtractedArgs {
  workspaceId: string;
  records: ExtractedRecord[];
  sourceName: string;
  documentId?: string | null;
  bySub: string;
  /** Confidence gate for the summary counts (job enforces it). */
  threshold: number;
}

export interface StageExtractedResult {
  batchId: string;
  sheetId: string;
  total: number;
  autoWrite: number;
  hold: number;
}

/** Persist extracted records as a synthetic sheet of import_rows (sensitive fields
 *  encrypted, email blind-indexed for dedupe, confidence recorded). Returns the
 *  sheetId and how the confidence gate will split the rows. */
export async function stageExtracted(args: StageExtractedArgs): Promise<StageExtractedResult> {
  const [batch] = await db()
    .insert(importBatches)
    .values({ workspaceId: args.workspaceId, documentId: args.documentId ?? null, filename: args.sourceName, mime: "application/x-extracted", status: "parsing", sheetCount: 1, createdBySub: args.bySub })
    .returning({ id: importBatches.id });
  const batchId = batch!.id;

  const [sheet] = await db()
    .insert(importSheets)
    .values({ workspaceId: args.workspaceId, batchId, name: "extracted", ord: 0, headerRow: 0, rowCount: args.records.length, colCount: 11 })
    .returning({ id: importSheets.id });
  const sheetId = sheet!.id;

  // A minimal column profile (structural names only — no values → no PII).
  const colNames = ["account.name", "account.domain", "contact.name", "contact.title", "contact.email", "contact.phone", "deal.name", "deal.value", "task.title", "task.priority", "note"];
  await db().insert(importColumns).values(
    colNames.map((name, ord) => ({ workspaceId: args.workspaceId, sheetId, ord, name, type: SENSITIVE_COLS.has(name) ? (name.endsWith("email") ? "email" : "phone") : "text", sensitive: SENSITIVE_COLS.has(name), nullFrac: 0, sampleJson: [] as string[] })),
  );

  let autoWrite = 0, hold = 0;
  const rowValues = args.records.map((rec, i) => {
    const all = recordToCells(rec);
    const cells: Record<string, string> = {};
    const sensitive: Record<string, string> = {};
    for (const [k, v] of Object.entries(all)) (SENSITIVE_COLS.has(k) ? sensitive : cells)[k] = v;
    const email = rec.contact?.email?.trim().toLowerCase();
    if (rec.confidence >= args.threshold) autoWrite++; else hold++;
    return {
      workspaceId: args.workspaceId,
      sheetId,
      rowIndex: i,
      cells,
      cellsEnc: Object.keys(sensitive).length ? encryptField(args.workspaceId, JSON.stringify(sensitive)) : null,
      dedupeKey: email ? blindIndex(args.workspaceId, "email", email) : null,
      confidence: rec.confidence,
      status: "new" as const,
    };
  });
  for (let i = 0; i < rowValues.length; i += 200) {
    await db().insert(importRows).values(rowValues.slice(i, i + 200));
  }

  await db().update(importBatches).set({ status: "ready" }).where(eq(importBatches.id, batchId));
  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.bySub, event: "extracted_staged", target: batchId });
  return { batchId, sheetId, total: args.records.length, autoWrite, hold };
}
