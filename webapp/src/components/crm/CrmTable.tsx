"use client";

/**
 * CRM table view (COMMS-CRM-DEPTH D4). A sortable, searchable table for one entity with
 * a column chooser surfacing custom fields, row multi-select + bulk tag, CSV export, and
 * saved views. Rows link into the record file. Data comes from /crm/[entity]/records
 * (custom values decrypted server-side; queryable forms drive sort).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Btn, Icon } from "@/components/primitives";
import type { CrmEntity } from "@/lib/domain/crm-enums";
import s from "@/components/common/screen.module.css";
import styles from "./CrmTable.module.css";

interface Column { key: string; label: string; kind: "standard" | "custom"; numeric?: boolean }
interface Cell { display: string; sort: string | number }
interface Row { id: string; cells: Record<string, Cell> }
interface SavedView { id: string; name: string; mine: boolean; shared: boolean; config: ViewConfig }
interface ViewConfig { columns: string[]; sort?: { key: string; dir: "asc" | "desc" }; search?: string }

const ENTITY_PATH: Record<CrmEntity, string> = { account: "accounts", deal: "deals", contact: "contacts" };

export function CrmTable({ workspaceId, slug, entity, canEdit }: { workspaceId: string; slug: string; entity: CrmEntity; canEdit: boolean }) {
  const router = useRouter();
  const base = `/api/workspaces/${workspaceId}/crm`;
  const [columns, setColumns] = useState<Column[]>([]);
  const [rows, setRows] = useState<Row[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [visible, setVisible] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" } | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [colMenu, setColMenu] = useState(false);
  const [views, setViews] = useState<SavedView[]>([]);
  const [bulkTag, setBulkTag] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    const [recRes, viewRes] = await Promise.all([
      fetch(`${base}/${entity}/records`).then((r) => (r.ok ? r.json() : { columns: [], rows: [], truncated: false })),
      fetch(`${base}/views?entity=${entity}`).then((r) => (r.ok ? r.json() : { views: [] })),
    ]);
    setColumns(recRes.columns);
    setRows(recRes.rows);
    setTruncated(recRes.truncated);
    setViews(viewRes.views ?? []);
    setVisible((prev) => (prev.size === 0 ? new Set(recRes.columns.filter((c: Column) => c.kind === "standard").map((c: Column) => c.key)) : prev));
    setSelected(new Set());
    setLoading(false);
  }, [base, entity]);

  useEffect(() => {
    void load();
  }, [load]);

  const visibleColumns = useMemo(() => columns.filter((c) => visible.has(c.key)), [columns, visible]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    let out = rows;
    if (q) out = rows.filter((r) => visibleColumns.some((c) => (r.cells[c.key]?.display ?? "").toLowerCase().includes(q)));
    if (sort) {
      const { key, dir } = sort;
      out = [...out].sort((a, b) => {
        const av = a.cells[key]?.sort ?? "";
        const bv = b.cells[key]?.sort ?? "";
        const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
        return dir === "asc" ? cmp : -cmp;
      });
    }
    return out;
  }, [rows, search, sort, visibleColumns]);

  function toggleSort(key: string) {
    setSort((p) => (p?.key === key ? { key, dir: p.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  }
  function toggleSelectAll() {
    setSelected((p) => (p.size === filtered.length ? new Set() : new Set(filtered.map((r) => r.id))));
  }
  function toggleRow(id: string) {
    setSelected((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  }

  function exportCsv() {
    const header = visibleColumns.map((c) => csv(c.label)).join(",");
    const lines = filtered.map((r) => visibleColumns.map((c) => csv(r.cells[c.key]?.display ?? "")).join(","));
    download(`${entity}s.csv`, [header, ...lines].join("\n"));
  }

  async function applyBulkTag() {
    if (!bulkTag.trim() || selected.size === 0) return;
    await fetch(`${base}/${entity}/bulk-tag`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ recordIds: Array.from(selected), label: bulkTag.trim() }),
    });
    setBulkTag("");
    await load();
  }

  async function saveCurrentView() {
    const name = prompt("Name this view:");
    if (!name?.trim()) return;
    await fetch(`${base}/views`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ entity, name: name.trim(), config: { columns: Array.from(visible), sort: sort ?? undefined, search: search || undefined } }),
    });
    await load();
  }
  function applyView(v: SavedView) {
    setVisible(new Set(v.config.columns));
    setSort(v.config.sort ?? null);
    setSearch(v.config.search ?? "");
  }
  async function removeView(viewId: string) {
    await fetch(`${base}/views`, { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ viewId }) });
    await load();
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.toolbar}>
        <div className={styles.searchBox}>
          <Icon name="search" size={14} />
          <input className={styles.search} placeholder={`Search ${entity}s…`} value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className={styles.colChooser}>
          <button className={styles.toolBtn} onClick={() => setColMenu((v) => !v)}>
            <Icon name="filter" size={13} /> Columns
          </button>
          {colMenu && (
            <div className={styles.colMenu} onMouseLeave={() => setColMenu(false)}>
              {columns.map((c) => (
                <label key={c.key} className={styles.colItem}>
                  <input
                    type="checkbox"
                    checked={visible.has(c.key)}
                    onChange={() => setVisible((p) => { const n = new Set(p); if (n.has(c.key)) n.delete(c.key); else n.add(c.key); return n; })}
                  />
                  {c.label}
                  {c.kind === "custom" && <span className={styles.customTag}>custom</span>}
                </label>
              ))}
            </div>
          )}
        </div>
        {views.length > 0 && (
          <select
            className={styles.viewSelect}
            defaultValue=""
            onChange={(e) => { const v = views.find((x) => x.id === e.target.value); if (v) applyView(v); }}
          >
            <option value="">Saved views…</option>
            {views.map((v) => (
              <option key={v.id} value={v.id}>{v.name}{v.shared ? " (shared)" : ""}</option>
            ))}
          </select>
        )}
        <span className={styles.spacer} />
        {canEdit && <button className={styles.toolBtn} onClick={saveCurrentView}><Icon name="star" size={13} /> Save view</button>}
        <button className={styles.toolBtn} onClick={exportCsv}><Icon name="download" size={13} /> CSV</button>
      </div>

      {selected.size > 0 && canEdit && (
        <div className={styles.bulkBar}>
          <span>{selected.size} selected</span>
          <input className={styles.bulkInput} placeholder="tag label" value={bulkTag} onChange={(e) => setBulkTag(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") applyBulkTag(); }} />
          <Btn variant="primary" size="sm" onClick={applyBulkTag} disabled={!bulkTag.trim()}>Tag selected</Btn>
          <button className={styles.toolBtn} onClick={() => setSelected(new Set())}>Clear</button>
        </div>
      )}

      {loading ? (
        <div className={s.empty}>Loading…</div>
      ) : rows.length === 0 ? (
        <div className={s.empty}>No {entity}s yet.</div>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                {canEdit && (
                  <th className={styles.checkCol}>
                    <input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleSelectAll} />
                  </th>
                )}
                {visibleColumns.map((c) => (
                  <th key={c.key} className={styles.th} onClick={() => toggleSort(c.key)}>
                    {c.label}
                    {sort?.key === c.key && <span className={styles.sortDir}>{sort.dir === "asc" ? "▲" : "▼"}</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr key={r.id} className={styles.tr}>
                  {canEdit && (
                    <td className={styles.checkCol} onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleRow(r.id)} />
                    </td>
                  )}
                  {visibleColumns.map((c, i) => (
                    <td
                      key={c.key}
                      className={`${styles.td} ${i === 0 ? styles.firstCell : ""}`}
                      onClick={() => router.push(`/w/${slug}/crm/${ENTITY_PATH[entity]}/${r.id}`)}
                    >
                      {r.cells[c.key]?.display || <span className={styles.dash}>—</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {truncated && <div className={styles.truncated}>Showing the first 2,000 records.</div>}
          {views.some((v) => v.mine) && (
            <div className={styles.myViews}>
              Your views:{" "}
              {views.filter((v) => v.mine).map((v) => (
                <span key={v.id} className={styles.viewChip}>
                  {v.name}
                  <button className={styles.viewX} onClick={() => removeView(v.id)} aria-label={`Delete ${v.name}`}><Icon name="x" size={10} /></button>
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function csv(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function download(name: string, content: string) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
