"use client";

/**
 * Imports panel (AGENTS_03). Lists dropped spreadsheets as sheets; per sheet it shows
 * the column profile, an editable column→CRM mapping, a dry-run preview (N new / M
 * updated / K held), and a one-click import with a live progress bar. The import runs
 * server-side in resumable slices; this panel drives it to completion by ticking.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DropZone } from "./DropZone";
import styles from "./ImportsPanel.module.css";

type SheetMeta = { id: string; name: string; rowCount: number; colCount: number };
type Batch = { batchId: string; filename: string; status: string; createdAt: string; sheets: SheetMeta[] };
type Job = { id: string; sheetId: string; status: string; cursor: number; total: number; created: number; updated: number; held: number; failed: number; done?: boolean };
type Column = { name: string; type: string; sensitive: boolean; nullFrac: number; samples: string[] };
type ColMap = { kind: "std"; target: string } | { kind: "custom"; entity: string; key: string; label: string; type: string } | { kind: "ignore" };
type Spec = { primaryEntity: string; columns: { column: string; map: ColMap }[]; dedupe: { account: string; contact: string } };
type Preview = { rows: number; created: number; updated: number; held: number; newAccounts: number; newContacts: number; newDeals: number; newTasks: number };

const STD_TARGETS = [
  ["ignore", "— Ignore —"],
  ["account.name", "Account · name"],
  ["account.domain", "Account · domain"],
  ["contact.name", "Contact · name"],
  ["contact.firstName", "Contact · first name"],
  ["contact.lastName", "Contact · last name"],
  ["contact.email", "Contact · email"],
  ["contact.title", "Contact · title"],
  ["contact.phone", "Contact · phone"],
  ["deal.name", "Deal · name"],
  ["deal.value", "Deal · value"],
  ["task.title", "Task · title"],
  ["custom:contact", "Custom field · on contact"],
  ["custom:account", "Custom field · on account"],
] as const;

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "field";
}

function mapToToken(m: ColMap): string {
  if (m.kind === "ignore") return "ignore";
  if (m.kind === "std") return m.target;
  return `custom:${m.entity}`;
}
function tokenToMap(token: string, column: string, type: string): ColMap {
  if (token === "ignore") return { kind: "ignore" };
  if (token.startsWith("custom:")) return { kind: "custom", entity: token.slice(7), key: slug(column), label: column, type };
  return { kind: "std", target: token };
}

export function ImportsPanel({ workspaceId, canEdit }: { workspaceId: string; canEdit: boolean }) {
  const base = `/api/workspaces/${workspaceId}`;
  const [batches, setBatches] = useState<Batch[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [sel, setSel] = useState<SheetMeta | null>(null);
  const [columns, setColumns] = useState<Column[]>([]);
  const [spec, setSpec] = useState<Spec | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const ticking = useRef(false);

  const loadTables = useCallback(async () => {
    const r = await fetch(`${base}/tables`);
    if (r.ok) {
      const d = (await r.json()) as { batches: Batch[]; jobs: Job[] };
      setBatches(d.batches);
      setJobs(d.jobs);
    }
  }, [base]);

  useEffect(() => { void loadTables(); }, [loadTables]);

  async function selectSheet(s: SheetMeta) {
    setSel(s); setPreview(null); setJob(null); setErr(null);
    const [schemaRes, mapRes] = await Promise.all([
      fetch(`${base}/tables/${s.id}`),
      fetch(`${base}/tables/${s.id}/mapping`),
    ]);
    if (schemaRes.ok) setColumns(((await schemaRes.json()) as { columns: Column[] }).columns);
    if (mapRes.ok) setSpec(((await mapRes.json()) as { spec: Spec }).spec);
  }

  function setColMap(column: string, token: string, type: string) {
    setSpec((prev) => prev ? { ...prev, columns: prev.columns.map((c) => c.column === column ? { column, map: tokenToMap(token, column, type) } : c) } : prev);
    setPreview(null);
  }

  async function saveMapping() {
    if (!sel || !spec) return;
    setBusy("save"); setErr(null);
    const r = await fetch(`${base}/tables/${sel.id}/mapping`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ spec }) });
    setBusy(null);
    if (!r.ok) setErr("Could not save mapping.");
  }

  async function runPreview() {
    if (!sel || !spec) return;
    setBusy("preview"); setErr(null);
    await saveMapping();
    const r = await fetch(`${base}/tables/${sel.id}/import`);
    setBusy(null);
    if (r.ok) setPreview(((await r.json()) as { preview: Preview }).preview);
    else setErr("Preview failed — check the mapping.");
  }

  const tickToDone = useCallback(async (jobId: string) => {
    if (ticking.current) return;
    ticking.current = true;
    try {
      for (let i = 0; i < 10000; i++) {
        const r = await fetch(`${base}/import-jobs/${jobId}/tick`, { method: "POST" });
        if (!r.ok) break;
        const p = (await r.json()) as Job;
        setJob(p);
        if (p.status === "done" || p.status === "failed") break;
      }
    } finally {
      ticking.current = false;
      void loadTables();
    }
  }, [base, loadTables]);

  async function startImport() {
    if (!sel || !spec) return;
    setBusy("import"); setErr(null);
    await saveMapping();
    const r = await fetch(`${base}/tables/${sel.id}/import`, { method: "POST" });
    setBusy(null);
    if (!r.ok) { setErr("Import could not start."); return; }
    const { jobId, progress } = (await r.json()) as { jobId: string; progress: Job };
    setJob(progress);
    if (progress.status !== "done") void tickToDone(jobId);
    else void loadTables();
  }

  const pct = job && job.total ? Math.min(100, Math.round((job.cursor / job.total) * 100)) : 0;
  const activeJobsForSheet = useMemo(() => jobs.filter((j) => sel && j.sheetId === sel.id), [jobs, sel]);

  return (
    <>
    {canEdit && <div className={styles.uploader}><DropZone workspaceId={workspaceId} scope={{}} onDone={() => void loadTables()} /></div>}
    <div className={styles.wrap}>
      <div className={styles.sidebar}>
        <div className={styles.sideHead}>Dropped tables</div>
        {batches.length === 0 && <div className={styles.empty}>No spreadsheets yet. Drop an .xlsx or .csv on the workspace.</div>}
        {batches.map((b) => (
          <div key={b.batchId} className={styles.batch}>
            <div className={styles.batchName} title={b.filename}>{b.filename}</div>
            {b.sheets.map((s) => (
              <button key={s.id} className={`${styles.sheet} ${sel?.id === s.id ? styles.sheetActive : ""}`} onClick={() => void selectSheet(s)}>
                <span className={styles.sheetName}>{s.name}</span>
                <span className={styles.sheetMeta}>{s.rowCount}×{s.colCount}</span>
              </button>
            ))}
          </div>
        ))}
      </div>

      <div className={styles.main}>
        {!sel && <div className={styles.placeholder}>Select a sheet to map its columns into the CRM.</div>}
        {sel && (
          <>
            <div className={styles.header}>
              <h2 className={styles.title}>{sel.name}</h2>
              <span className={styles.sub}>{sel.rowCount} rows · {sel.colCount} columns</span>
            </div>

            {err && <div className={styles.error}>{err}</div>}

            <div className={styles.mapping}>
              {columns.map((c) => {
                const cm = spec?.columns.find((x) => x.column === c.name)?.map ?? { kind: "ignore" as const };
                return (
                  <div key={c.name} className={styles.mapRow}>
                    <div className={styles.colInfo}>
                      <span className={styles.colName}>{c.name}</span>
                      <span className={styles.colType}>{c.type}{c.sensitive ? " · sensitive" : ""}</span>
                      {c.samples.length > 0 && <span className={styles.samples}>{c.samples.slice(0, 3).join(", ")}</span>}
                    </div>
                    <select
                      className={styles.select}
                      disabled={!canEdit}
                      value={mapToToken(cm)}
                      onChange={(e) => setColMap(c.name, e.target.value, c.type)}
                    >
                      {STD_TARGETS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                    </select>
                  </div>
                );
              })}
            </div>

            {spec && (
              <div className={styles.dedupe}>
                Dedupe — accounts by <strong>{spec.dedupe.account}</strong>, contacts by <strong>{spec.dedupe.contact}</strong>
              </div>
            )}

            {canEdit && (
              <div className={styles.actions}>
                <button className={styles.btn} disabled={busy !== null} onClick={() => void runPreview()}>
                  {busy === "preview" ? "Previewing…" : "Preview"}
                </button>
                <button className={styles.btnPrimary} disabled={busy !== null || !!job} onClick={() => void startImport()}>
                  {busy === "import" ? "Starting…" : "Import into CRM"}
                </button>
              </div>
            )}

            {preview && !job && (
              <div className={styles.preview}>
                <strong>Preview:</strong> {preview.created} new · {preview.updated} updated · {preview.held} held across {preview.rows} rows
                <span className={styles.previewDetail}> ({preview.newAccounts} accounts, {preview.newContacts} contacts{preview.newDeals ? `, ${preview.newDeals} deals` : ""}{preview.newTasks ? `, ${preview.newTasks} tasks` : ""})</span>
              </div>
            )}

            {job && (
              <div className={styles.progress}>
                <div className={styles.progressBar}><div className={styles.progressFill} style={{ width: `${pct}%` }} /></div>
                <div className={styles.progressText}>
                  {job.status === "done" ? "Done" : job.status === "failed" ? "Failed" : "Importing…"} — {job.cursor}/{job.total} rows · {job.created} created · {job.updated} updated · {job.held} held{job.failed ? ` · ${job.failed} failed` : ""}
                </div>
              </div>
            )}

            {activeJobsForSheet.length > 0 && !job && (
              <div className={styles.priorJobs}>
                Prior imports: {activeJobsForSheet.map((j) => `${j.status} ${j.cursor}/${j.total}`).join(" · ")}
              </div>
            )}
          </>
        )}
      </div>
    </div>
    </>
  );
}
