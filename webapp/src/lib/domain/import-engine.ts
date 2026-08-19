/**
 * Bulk-import engine (AGENTS_03). Turns row-store rows into deduped CRM records via an
 * approved MappingSpec — server-side, in BOUNDED, RESUMABLE slices, so a 1,000-row
 * import never runs through the model or a single long request.
 *
 * One `resolveRow` drives both the dry-run PREVIEW (counts only) and real EXECUTION,
 * via an `Upserter` abstraction — so the preview a human approves is exactly what runs.
 * Dedupe: accounts by domain|name, contacts by email blind-index|name+account.
 */
import { and, asc, eq, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { importRows, importSheets, importJobs, importMappings, accounts, contacts } from "@/lib/db/schema";
import { decryptField, blindIndex } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { createAccount, createContact, createDeal } from "./crm";
import { createProject, createTask } from "./pm";
import { listFieldDefs, createFieldDef } from "./crm-fields";
import { setFieldValue } from "./crm-fields";
import { columnsFor, suggestMapping, type MappingSpec } from "./import-map";
import { getSheetSchema } from "./tables-repo";
import type { CrmEntity } from "./crm-enums";

export const IMPORT_SLICE = 200;

// ── mapping persistence ──────────────────────────────────────────────────────

export async function getMapping(workspaceId: string, sheetId: string): Promise<{ id: string; spec: MappingSpec; approved: boolean } | null> {
  const [m] = await db()
    .select()
    .from(importMappings)
    .where(and(eq(importMappings.workspaceId, workspaceId), eq(importMappings.sheetId, sheetId)))
    .limit(1);
  return m ? { id: m.id, spec: m.spec as MappingSpec, approved: m.approved } : null;
}

export async function saveMapping(args: { workspaceId: string; sheetId: string; spec: MappingSpec; bySub: string; approved?: boolean }): Promise<string> {
  // Race-safe upsert against the (workspace_id, sheet_id) unique index. The old
  // read-then-insert-or-update had a TOCTOU gap: two near-simultaneous tables.map
  // calls (or a crm.import self-heal racing tables.map) could both miss the existing
  // row and then collide on the unique index, throwing and leaving no mapping saved —
  // one of the ways the import chain "broke at tables.map". `approved` is only
  // overwritten when explicitly passed, so re-saving a draft never silently un-approves
  // (or approves) an existing mapping.
  const [row] = await db()
    .insert(importMappings)
    .values({ workspaceId: args.workspaceId, sheetId: args.sheetId, spec: args.spec, approved: args.approved ?? false, createdBySub: args.bySub })
    .onConflictDoUpdate({
      target: [importMappings.workspaceId, importMappings.sheetId],
      set: { spec: args.spec, updatedAt: new Date(), ...(args.approved !== undefined ? { approved: args.approved } : {}) },
    })
    .returning({ id: importMappings.id });
  return row!.id;
}

/**
 * Return the sheet's mapping, generating + persisting a suggested draft if none exists
 * yet. This makes the ingestion chain self-healing: `crm.import` no longer hard-blocks
 * when `tables.map` was never called (or its save failed transiently) — it falls back
 * to the same suggested mapping `tables.map` would have produced. Returns null only when
 * the sheet genuinely doesn't exist. `autocreated` lets callers tell the user a draft
 * was inferred so they can review it.
 */
export async function ensureMapping(
  workspaceId: string,
  sheetId: string,
  bySub: string,
): Promise<{ id: string; spec: MappingSpec; approved: boolean; autocreated: boolean } | null> {
  const existing = await getMapping(workspaceId, sheetId);
  if (existing) return { ...existing, autocreated: false };
  const schema = await getSheetSchema(workspaceId, sheetId);
  if (!schema) return null;
  const spec = suggestMapping(
    schema.columns.map((c) => ({ name: c.name, type: c.type as never, sensitive: c.sensitive, nullFrac: c.nullFrac, samples: c.samples })),
  );
  const id = await saveMapping({ workspaceId, sheetId, spec, bySub });
  return { id, spec, approved: false, autocreated: true };
}

export async function approveMapping(workspaceId: string, mappingId: string): Promise<void> {
  await db().update(importMappings).set({ approved: true, updatedAt: new Date() }).where(and(eq(importMappings.workspaceId, workspaceId), eq(importMappings.id, mappingId)));
}

// ── row loading (full values, incl. decrypted sensitive) ─────────────────────

type RowVals = Record<string, string>;

/** A loaded row: its id + extraction confidence (null = trusted structured source)
 *  alongside the decrypted value map. The id/confidence drive the confidence gate
 *  and per-row status writes; preview ignores them. */
interface LoadedRow {
  id: string;
  confidence: number | null;
  vals: RowVals;
}

async function loadRows(workspaceId: string, sheetId: string, offset: number, limit: number): Promise<LoadedRow[]> {
  const rows = await db()
    .select({ id: importRows.id, confidence: importRows.confidence, cells: importRows.cells, cellsEnc: importRows.cellsEnc })
    .from(importRows)
    .where(and(eq(importRows.workspaceId, workspaceId), eq(importRows.sheetId, sheetId)))
    .orderBy(asc(importRows.rowIndex))
    .offset(offset)
    .limit(limit);
  return rows.map((r) => {
    const vals: RowVals = { ...(r.cells as RowVals) };
    if (r.cellsEnc) {
      try {
        Object.assign(vals, JSON.parse(decryptField(workspaceId, r.cellsEnc)) as RowVals);
      } catch {
        /* skip */
      }
    }
    return { id: r.id, confidence: r.confidence, vals };
  });
}

/** The confidence gate (ADR-UDI-03), pure + exported for test. A row is held when
 *  the job sets a threshold AND the row carries a confidence below it. Structured
 *  rows (confidence null) and jobs with no threshold (null) always pass. */
export function heldByConfidence(minConfidence: number | null, rowConfidence: number | null): boolean {
  return minConfidence != null && rowConfidence != null && rowConfidence < minConfidence;
}

async function setRowStatus(rowId: string, status: "imported" | "held" | "skipped"): Promise<void> {
  await db().update(importRows).set({ status }).where(eq(importRows.id, rowId));
}

// ── upserter abstraction (shared by preview + execute) ───────────────────────

export interface Upserter {
  upsertAccount(name: string | null, domain: string | null): Promise<{ id: string; created: boolean } | null>;
  upsertContact(name: string, title: string | null, email: string | null, accountId: string | null): Promise<{ id: string; created: boolean }>;
  createDealFor(name: string, valueMinor: number, accountId: string | null): Promise<void>;
  createTaskFor(title: string, priority: string | null): Promise<void>;
  setCustom(entity: CrmEntity, recordId: string, key: string, label: string, type: string, value: string): Promise<void>;
}

interface ExistingMaps {
  accByDomain: Map<string, string>;
  accByName: Map<string, string>;
  contactByEmailKey: Map<string, string>;
  contactByNameAcct: Map<string, string>;
}

async function loadExisting(workspaceId: string): Promise<ExistingMaps> {
  const accs = await db().select({ id: accounts.id, name: accounts.name, domain: accounts.domain }).from(accounts).where(eq(accounts.workspaceId, workspaceId));
  const cts = await db().select({ id: contacts.id, name: contacts.name, accountId: contacts.accountId, emailKey: contacts.emailKey }).from(contacts).where(eq(contacts.workspaceId, workspaceId));
  const m: ExistingMaps = { accByDomain: new Map(), accByName: new Map(), contactByEmailKey: new Map(), contactByNameAcct: new Map() };
  for (const a of accs) {
    if (a.domain) m.accByDomain.set(a.domain.toLowerCase(), a.id);
    m.accByName.set(a.name.toLowerCase(), a.id);
  }
  for (const c of cts) {
    if (c.emailKey) m.contactByEmailKey.set(c.emailKey, c.id);
    m.contactByNameAcct.set(`${c.name.toLowerCase()}|${c.accountId ?? ""}`, c.id);
  }
  return m;
}

/** Real upserter — writes through to CRM + keeps dedupe maps warm within/across slices. */
function realUpserter(workspaceId: string, bySub: string, maps: ExistingMaps, spec: MappingSpec): Upserter {
  const defCache = new Map<CrmEntity, Map<string, string>>(); // entity → key → fieldId
  let taskProjectId: string | null = null;

  async function fieldId(entity: CrmEntity, key: string, label: string, type: string): Promise<string> {
    if (!defCache.has(entity)) {
      const defs = await listFieldDefs(workspaceId, entity, { includeDisabled: true });
      defCache.set(entity, new Map(defs.map((d) => [d.key, d.id])));
    }
    const cache = defCache.get(entity)!;
    if (cache.has(key)) return cache.get(key)!;
    const sensitive = type === "email" || type === "phone" || /addr|street|zip|ssn|dob/i.test(key);
    // crm field types are constrained; fall back to text for anything unusual.
    const okTypes = new Set(["text", "longtext", "number", "currency", "date", "select", "multiselect", "boolean", "url", "email", "phone", "user"]);
    const def = await createFieldDef({ workspaceId, entity, key, label, type: (okTypes.has(type) ? type : "text") as never, sensitive, createdBy: bySub });
    cache.set(key, def.id);
    return def.id;
  }

  return {
    async upsertAccount(name, domain) {
      const dkey = domain?.toLowerCase() || null;
      const nkey = name?.toLowerCase() || null;
      if (spec.dedupe.account === "domain" && dkey && maps.accByDomain.has(dkey)) return { id: maps.accByDomain.get(dkey)!, created: false };
      if (nkey && maps.accByName.has(nkey)) return { id: maps.accByName.get(nkey)!, created: false };
      if (!name && !domain) return null;
      const row = await createAccount(workspaceId, name || domain!, domain ?? null, bySub);
      if (dkey) maps.accByDomain.set(dkey, row.id);
      if (nkey) maps.accByName.set(nkey, row.id);
      return { id: row.id, created: true };
    },
    async upsertContact(name, title, email, accountId) {
      const ekey = email ? blindIndex(workspaceId, "email", email.trim().toLowerCase()) : null;
      if (spec.dedupe.contact === "email" && ekey && maps.contactByEmailKey.has(ekey)) return { id: maps.contactByEmailKey.get(ekey)!, created: false };
      const nkey = `${name.toLowerCase()}|${accountId ?? ""}`;
      if (spec.dedupe.contact !== "email" && maps.contactByNameAcct.has(nkey)) return { id: maps.contactByNameAcct.get(nkey)!, created: false };
      const row = await createContact({ workspaceId, name, title, accountId, ownerSub: bySub, email });
      if (ekey) maps.contactByEmailKey.set(ekey, row.id);
      maps.contactByNameAcct.set(nkey, row.id);
      return { id: row.id, created: true };
    },
    async createDealFor(name, valueMinor, accountId) {
      if (!accountId) return;
      await createDeal({ workspaceId, accountId, name, valueMinor, ownerSub: bySub });
    },
    async createTaskFor(title, priority) {
      if (!taskProjectId) {
        const proj = await createProject(workspaceId, spec.createTasks?.projectName || "Imported");
        taskProjectId = proj.id;
      }
      await createTask({ workspaceId, projectId: taskProjectId, title, priority });
    },
    async setCustom(entity, recordId, key, label, type, value) {
      const fid = await fieldId(entity, key, label, type);
      await setFieldValue({ workspaceId, entity, recordId, fieldId: fid, raw: value, bySub, byAgent: true });
    },
  };
}

/** Dry upserter — no writes; assigns synthetic ids and mutates local maps so dedupe
 *  behaves exactly like the real run, for an accurate preview. */
function dryUpserter(maps: ExistingMaps, spec: MappingSpec, counts: PreviewCounts): Upserter {
  let n = 0;
  const synth = () => `dry:${++n}`;
  return {
    async upsertAccount(name, domain) {
      const dkey = domain?.toLowerCase() || null;
      const nkey = name?.toLowerCase() || null;
      if (spec.dedupe.account === "domain" && dkey && maps.accByDomain.has(dkey)) return { id: maps.accByDomain.get(dkey)!, created: false };
      if (nkey && maps.accByName.has(nkey)) return { id: maps.accByName.get(nkey)!, created: false };
      if (!name && !domain) return null;
      const id = synth();
      if (dkey) maps.accByDomain.set(dkey, id);
      if (nkey) maps.accByName.set(nkey, id);
      counts.newAccounts++;
      return { id, created: true };
    },
    async upsertContact(name, _title, email, accountId) {
      const ekey = email ? blindIndex("preview", "email", email.trim().toLowerCase()) : null;
      if (spec.dedupe.contact === "email" && ekey && maps.contactByEmailKey.has(ekey)) return { id: maps.contactByEmailKey.get(ekey)!, created: false };
      const nkey = `${name.toLowerCase()}|${accountId ?? ""}`;
      if (spec.dedupe.contact !== "email" && maps.contactByNameAcct.has(nkey)) return { id: maps.contactByNameAcct.get(nkey)!, created: false };
      const id = synth();
      if (ekey) maps.contactByEmailKey.set(ekey, id);
      maps.contactByNameAcct.set(nkey, id);
      counts.newContacts++;
      return { id, created: true };
    },
    async createDealFor(_name, _valueMinor, accountId) {
      if (accountId) counts.newDeals++;
    },
    async createTaskFor() {
      counts.newTasks++;
    },
    async setCustom() {
      /* counts elsewhere */
    },
  };
}

// ── the shared resolver ──────────────────────────────────────────────────────

type Outcome = "created" | "updated" | "held";

function first(vals: RowVals, cols: string[]): string {
  for (const c of cols) {
    const v = vals[c]?.trim();
    if (v) return v;
  }
  return "";
}

function parseMoneyMinor(s: string): number {
  const n = parseFloat(s.replace(/[^0-9.-]/g, ""));
  return Number.isFinite(n) ? Math.round(n * 100) : 0;
}

export async function resolveRow(spec: MappingSpec, vals: RowVals, up: Upserter): Promise<Outcome> {
  const accountName = first(vals, columnsFor(spec, "account.name"));
  const domain = first(vals, columnsFor(spec, "account.domain"));
  const fullName = first(vals, columnsFor(spec, "contact.name"));
  const firstName = first(vals, columnsFor(spec, "contact.firstName"));
  const lastName = first(vals, columnsFor(spec, "contact.lastName"));
  const email = first(vals, columnsFor(spec, "contact.email"));
  const title = first(vals, columnsFor(spec, "contact.title"));
  const phone = first(vals, columnsFor(spec, "contact.phone"));
  const dealName = first(vals, columnsFor(spec, "deal.name"));
  const dealValue = first(vals, columnsFor(spec, "deal.value"));
  const taskTitle = first(vals, columnsFor(spec, "task.title"));
  const taskPriority = first(vals, columnsFor(spec, "task.priority"));

  const contactName = fullName || [firstName, lastName].filter(Boolean).join(" ").trim() || (email ? email.split("@")[0]! : "");

  // Account (parent).
  let accountId: string | null = null;
  if (accountName || domain) {
    const acc = await up.upsertAccount(accountName || null, domain || null);
    accountId = acc?.id ?? null;
    for (const cm of spec.columns) {
      if (cm.map.kind === "custom" && cm.map.entity === "account" && accountId && vals[cm.column]?.trim())
        await up.setCustom("account", accountId, cm.map.key, cm.map.label, cm.map.type, vals[cm.column]!.trim());
    }
  }

  let outcome: Outcome | null = null;

  // Contact (primary for most sheets).
  if (contactName) {
    const c = await up.upsertContact(contactName, title || null, email || null, accountId);
    outcome = c.created ? "created" : "updated";
    if (phone) await up.setCustom("contact", c.id, "phone", "Phone", "phone", phone);
    for (const cm of spec.columns) {
      if (cm.map.kind === "custom" && cm.map.entity === "contact" && vals[cm.column]?.trim())
        await up.setCustom("contact", c.id, cm.map.key, cm.map.label, cm.map.type, vals[cm.column]!.trim());
    }
  }

  // Deal (optional).
  if ((dealName || dealValue) && accountId) {
    await up.createDealFor(dealName || `${accountName || contactName} — imported`, parseMoneyMinor(dealValue), accountId);
    if (!outcome) outcome = "created";
  }

  // Task (optional — prioritized lists).
  if (spec.createTasks || taskTitle) {
    const t = taskTitle || contactName || accountName;
    if (t) {
      await up.createTaskFor(t, taskPriority || null);
      if (!outcome) outcome = "created";
    }
  }

  if (!outcome && accountId) outcome = "updated"; // account-only sheet
  return outcome ?? "held";
}

// ── preview ──────────────────────────────────────────────────────────────────

export interface PreviewCounts {
  rows: number;
  created: number;
  updated: number;
  held: number;
  newAccounts: number;
  newContacts: number;
  newDeals: number;
  newTasks: number;
}

export async function previewImport(workspaceId: string, sheetId: string, spec: MappingSpec, sampleLimit = 2000): Promise<PreviewCounts> {
  const maps = await loadExisting(workspaceId);
  const counts: PreviewCounts = { rows: 0, created: 0, updated: 0, held: 0, newAccounts: 0, newContacts: 0, newDeals: 0, newTasks: 0 };
  const up = dryUpserter(maps, spec, counts);
  const rows = await loadRows(workspaceId, sheetId, 0, sampleLimit);
  for (const r of rows) {
    counts.rows++;
    const outcome = await resolveRow(spec, r.vals, up);
    counts[outcome]++;
  }
  return counts;
}

// ── job (resumable execution) ────────────────────────────────────────────────

export async function createImportJob(args: {
  workspaceId: string;
  sheetId: string;
  mappingId: string;
  filter?: unknown;
  bySub: string;
  /** UDI: rows with confidence below this are held for review instead of written.
   *  Omit/null to write every row (tabular + JSON, which carry no confidence). */
  minConfidence?: number | null;
}): Promise<string> {
  const [{ total } = { total: 0 }] = await db()
    .select({ total: sql<number>`count(*)::int` })
    .from(importRows)
    .where(and(eq(importRows.workspaceId, args.workspaceId), eq(importRows.sheetId, args.sheetId)));
  const [row] = await db()
    .insert(importJobs)
    .values({ workspaceId: args.workspaceId, sheetId: args.sheetId, mappingId: args.mappingId, filterJson: args.filter ?? null, minConfidence: args.minConfidence ?? null, status: "queued", total: Number(total) || 0, createdBySub: args.bySub })
    .returning({ id: importJobs.id });
  return row!.id;
}

export interface JobProgress {
  id: string;
  status: string;
  cursor: number;
  total: number;
  created: number;
  updated: number;
  held: number;
  failed: number;
  done: boolean;
}

/** Process the next ≤maxRows of a job. Idempotent-ish (dedupe absorbs re-runs). */
export async function runImportSlice(workspaceId: string, jobId: string, maxRows = IMPORT_SLICE): Promise<JobProgress> {
  const [job] = await db().select().from(importJobs).where(and(eq(importJobs.workspaceId, workspaceId), eq(importJobs.id, jobId))).limit(1);
  if (!job) throw new Error("job not found");
  if (job.status === "done" || job.status === "failed") return brief(job);

  const mapping = job.mappingId ? await db().select().from(importMappings).where(eq(importMappings.id, job.mappingId)).limit(1) : [];
  const spec = mapping[0]?.spec as MappingSpec | undefined;
  if (!spec) {
    await db().update(importJobs).set({ status: "failed", errorText: "mapping missing", updatedAt: new Date() }).where(eq(importJobs.id, jobId));
    return { ...brief(job), status: "failed" };
  }

  await db().update(importJobs).set({ status: "running", updatedAt: new Date() }).where(eq(importJobs.id, jobId));
  const maps = await loadExisting(workspaceId);
  const up = realUpserter(workspaceId, job.createdBySub, maps, spec);

  const rows = await loadRows(workspaceId, job.sheetId, job.cursor, maxRows);
  const minConf = job.minConfidence;
  let created = 0, updated = 0, held = 0, failed = 0;
  for (const r of rows) {
    // UDI confidence gate: a model-extracted row below the job threshold is NOT
    // written — it is held for HITL review (status 'held', flushable on approval).
    if (heldByConfidence(minConf, r.confidence)) {
      held++;
      await setRowStatus(r.id, "held");
      continue;
    }
    try {
      const o = await resolveRow(spec, r.vals, up);
      if (o === "created") created++;
      else if (o === "updated") updated++;
      else held++;
      // 'held' from resolveRow = unmappable (no account/contact); park as 'skipped'
      // so a review flush doesn't keep re-holding rows that can never resolve.
      await setRowStatus(r.id, o === "held" ? "skipped" : "imported");
    } catch {
      failed++;
      await setRowStatus(r.id, "skipped");
    }
  }

  const cursor = job.cursor + rows.length;
  const done = cursor >= job.total || rows.length === 0;
  await db()
    .update(importJobs)
    .set({
      cursor,
      createdCount: job.createdCount + created,
      updatedCount: job.updatedCount + updated,
      heldCount: job.heldCount + held,
      failedCount: job.failedCount + failed,
      status: done ? "done" : "queued",
      updatedAt: new Date(),
    })
    .where(eq(importJobs.id, jobId));

  if (done) await appendAudit({ workspaceId, actorSub: job.createdBySub, event: "table_import_done", target: jobId });

  return {
    id: jobId,
    status: done ? "done" : "queued",
    cursor,
    total: job.total,
    created: job.createdCount + created,
    updated: job.updatedCount + updated,
    held: job.heldCount + held,
    failed: job.failedCount + failed,
    done,
  };
}

export async function getJob(workspaceId: string, jobId: string): Promise<JobProgress | null> {
  const [job] = await db().select().from(importJobs).where(and(eq(importJobs.workspaceId, workspaceId), eq(importJobs.id, jobId))).limit(1);
  return job ? brief(job) : null;
}

/** Count rows a job held for confidence review (status 'held') on its sheet. */
export async function countHeldRows(workspaceId: string, jobId: string): Promise<number> {
  const [job] = await db().select({ sheetId: importJobs.sheetId }).from(importJobs).where(and(eq(importJobs.workspaceId, workspaceId), eq(importJobs.id, jobId))).limit(1);
  if (!job) return 0;
  const [{ n } = { n: 0 }] = await db()
    .select({ n: sql<number>`count(*)::int` })
    .from(importRows)
    .where(and(eq(importRows.workspaceId, workspaceId), eq(importRows.sheetId, job.sheetId), eq(importRows.status, "held")));
  return Number(n) || 0;
}

/** HITL flush: a human approved the held rows — write them regardless of confidence.
 *  Bounded to one slice; safe to call repeatedly until it returns 0 remaining. */
export async function flushHeldRows(workspaceId: string, jobId: string, maxRows = IMPORT_SLICE): Promise<{ written: number; remaining: number }> {
  const [job] = await db().select().from(importJobs).where(and(eq(importJobs.workspaceId, workspaceId), eq(importJobs.id, jobId))).limit(1);
  if (!job) throw new Error("job not found");
  const spec = job.mappingId ? ((await db().select().from(importMappings).where(eq(importMappings.id, job.mappingId)).limit(1))[0]?.spec as MappingSpec | undefined) : undefined;
  if (!spec) throw new Error("mapping missing");

  const held = await db()
    .select({ id: importRows.id, confidence: importRows.confidence, cells: importRows.cells, cellsEnc: importRows.cellsEnc })
    .from(importRows)
    .where(and(eq(importRows.workspaceId, workspaceId), eq(importRows.sheetId, job.sheetId), eq(importRows.status, "held")))
    .orderBy(asc(importRows.rowIndex))
    .limit(maxRows);

  const maps = await loadExisting(workspaceId);
  const up = realUpserter(workspaceId, job.createdBySub, maps, spec);
  let written = 0, created = 0, updated = 0;
  for (const r of held) {
    const vals: RowVals = { ...(r.cells as RowVals) };
    if (r.cellsEnc) {
      try { Object.assign(vals, JSON.parse(decryptField(workspaceId, r.cellsEnc)) as RowVals); } catch { /* skip */ }
    }
    try {
      const o = await resolveRow(spec, vals, up);
      await setRowStatus(r.id, o === "held" ? "skipped" : "imported");
      if (o === "created") created++;
      else if (o === "updated") updated++;
      if (o !== "held") written++;
    } catch {
      await setRowStatus(r.id, "skipped");
    }
  }

  await db()
    .update(importJobs)
    .set({ createdCount: job.createdCount + created, updatedCount: job.updatedCount + updated, heldCount: Math.max(0, job.heldCount - written), updatedAt: new Date() })
    .where(eq(importJobs.id, jobId));

  const remaining = await countHeldRows(workspaceId, jobId);
  await appendAudit({ workspaceId, actorSub: job.createdBySub, event: "ingest_review_flush", target: `${jobId}:${written}` });
  return { written, remaining };
}

/** Queued/running jobs across all workspaces — for the unattended cron tick. */
export async function listActiveJobs(limit = 20): Promise<{ workspaceId: string; id: string }[]> {
  const rows = await db()
    .select({ workspaceId: importJobs.workspaceId, id: importJobs.id, status: importJobs.status })
    .from(importJobs)
    .where(sql`${importJobs.status} in ('queued','running')`)
    .orderBy(asc(importJobs.updatedAt))
    .limit(limit);
  return rows.map((r) => ({ workspaceId: r.workspaceId, id: r.id }));
}

function brief(job: typeof importJobs.$inferSelect): JobProgress {
  return {
    id: job.id,
    status: job.status,
    cursor: job.cursor,
    total: job.total,
    created: job.createdCount,
    updated: job.updatedCount,
    held: job.heldCount,
    failed: job.failedCount,
    done: job.status === "done",
  };
}

/** Sheet row-count helper (for tooling). */
export async function sheetRowCount(workspaceId: string, sheetId: string): Promise<number> {
  const [sh] = await db().select({ n: importSheets.rowCount }).from(importSheets).where(and(eq(importSheets.workspaceId, workspaceId), eq(importSheets.id, sheetId))).limit(1);
  return sh?.n ?? 0;
}
