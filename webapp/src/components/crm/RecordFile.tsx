"use client";

/**
 * CRM record FILE (COMMS-CRM-DEPTH §6). The deep, clickable view of one
 * account/deal/contact: Overview (standard + dynamic custom fields, inline-editable),
 * Notes/Journal (typed entries + composer), Activity (auto feed), Related (clickable
 * sub-records), Documents, and trust-tiered Memories. Human edits are direct (RBAC
 * CreateRecord); agent writes go through the HITL approvals queue (CRM-D3).
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Avatar, Btn, Icon, SurfBadge, DataChip } from "@/components/primitives";
import { DropZone } from "./DropZone";
import { Attachment } from "@/components/attachments/Attachment";
import type { RecordFile as RecordFileData } from "@/lib/domain/crm-file";
import type { FieldWithValue, FieldDef } from "@/lib/domain/crm-fields";
import { CRM_NOTE_TYPES, type CrmEntity, type CrmNoteType } from "@/lib/domain/crm-enums";
import s from "@/components/common/screen.module.css";
import styles from "./RecordFile.module.css";

type Tab = "overview" | "notes" | "activity" | "related" | "documents" | "memories";

const ENTITY_PATH: Record<CrmEntity, string> = { account: "accounts", deal: "deals", contact: "contacts" };

function displayField(f: FieldWithValue): string {
  const { def, value } = f;
  if (value == null || value === "") return "—";
  if (def.type === "boolean") return value === "true" ? "Yes" : "No";
  if (def.type === "select") return def.options.find((o) => o.key === value)?.label ?? value;
  if (def.type === "multiselect") {
    return value.split(",").map((k) => def.options.find((o) => o.key === k.trim())?.label ?? k.trim()).join(", ");
  }
  if (def.type === "date") {
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? new Date(ms).toLocaleDateString() : value;
  }
  return value;
}

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function RecordFile({
  file,
  slug,
  workspaceId,
  backHref,
  canEdit = false,
  canManageFields = false,
  canDelete = false,
}: {
  file: RecordFileData;
  slug: string;
  workspaceId: string;
  backHref: string;
  canEdit?: boolean;
  canManageFields?: boolean;
  canDelete?: boolean;
}) {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("overview");
  const [deleting, setDeleting] = useState(false);
  const base = `/api/workspaces/${workspaceId}/crm/${file.entity}/${file.recordId}`;

  async function deleteRecord() {
    if (!confirm(`Delete this ${file.entity}? This can't be undone.`)) return;
    setDeleting(true);
    const r = await fetch(base, { method: "DELETE" });
    if (r.ok) {
      router.push(backHref);
      router.refresh();
      return;
    }
    setDeleting(false);
    const data = (await r.json().catch(() => ({}))) as { error?: string; message?: string };
    alert(data.message ?? (data.error === "account_has_children" ? "Delete its deals and contacts first." : "Couldn't delete this record."));
  }

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: "overview", label: "Overview" },
    { key: "notes", label: "Notes / Journal", count: file.notes.length },
    { key: "activity", label: "Activity", count: file.activity.length },
    { key: "related", label: "Related", count: file.related.reduce((n, g) => n + g.items.length, 0) },
    { key: "documents", label: "Documents", count: file.documents.length },
    { key: "memories", label: "Memories", count: file.memories.length },
  ];

  return (
    <div className={s.wrap}>
      <header className={styles.head}>
        <div className={styles.headTop}>
          <Link href={backHref} className={styles.back}>
            <Icon name="anchor" size={13} /> Back to CRM
          </Link>
          <div className={styles.headActions}>
            <Link href={`/w/${slug}/agents`} className={styles.askLink}>
              <Icon name="agents" size={13} /> Ask an agent about this {file.entity}
            </Link>
            {canDelete && (
              <button className={styles.deleteBtn} onClick={deleteRecord} disabled={deleting}>
                <Icon name="x" size={12} /> {deleting ? "Deleting…" : "Delete"}
              </button>
            )}
          </div>
        </div>
        <div className={styles.headMain}>
          <Avatar name={file.title} size="lg" />
          <div className={styles.headText}>
            <h1 className={styles.title}>{file.title}</h1>
            {file.subtitle && <div className={styles.subtitle}>{file.subtitle}</div>}
            <TagRow file={file} base={base} canEdit={canEdit} onChange={() => router.refresh()} />
          </div>
        </div>
        <div className={styles.stats}>
          {file.headerStats.map((st) => (
            <div key={st.label} className={styles.stat}>
              <div className={styles.statLabel}>{st.label}</div>
              <div className={styles.statValue}>{st.value}</div>
            </div>
          ))}
        </div>
      </header>

      <nav className={styles.tabs}>
        {tabs.map((t) => (
          <button key={t.key} className={`${styles.tab} ${tab === t.key ? styles.tabActive : ""}`} onClick={() => setTab(t.key)}>
            {t.label}
            {t.count != null && t.count > 0 && <span className={styles.tabCount}>{t.count}</span>}
          </button>
        ))}
      </nav>

      <div className={styles.body}>
        {tab === "overview" && (
          <Overview file={file} base={base} canEdit={canEdit} canManageFields={canManageFields} slug={slug} onSaved={() => router.refresh()} />
        )}

        {tab === "notes" && (
          <div className={styles.notes}>
            {canEdit && <NoteComposer base={base} onAdded={() => router.refresh()} />}
            {file.notes.length === 0 ? (
              <div className={s.empty}>No notes or journal entries yet.</div>
            ) : (
              file.notes.map((n) => (
                <div key={n.id} className={styles.note}>
                  <div className={styles.noteHead}>
                    <SurfBadge variant="outline">{n.type}</SurfBadge>
                    {n.pinned && <Icon name="star" size={12} />}
                    {n.byAgent && <SurfBadge variant="agent">AGENT</SurfBadge>}
                    <span className={styles.noteWhen}>{when(n.createdAt)}</span>
                  </div>
                  {n.title && <div className={styles.noteTitle}>{n.title}</div>}
                  <div className={styles.noteBody}>{n.body}</div>
                </div>
              ))
            )}
          </div>
        )}

        {tab === "activity" && (
          <div className={styles.activity}>
            {file.activity.length === 0 ? (
              <div className={s.empty}>No activity yet.</div>
            ) : (
              file.activity.map((a) => (
                <div key={a.id} className={styles.act}>
                  <span className={styles.actDot} />
                  <span className={styles.actSummary}>{a.summary}</span>
                  {a.byAgent && <SurfBadge variant="agent">AGENT</SurfBadge>}
                  <span className={styles.actWhen}>{when(a.createdAt)}</span>
                </div>
              ))
            )}
          </div>
        )}

        {tab === "related" && (
          <div className={styles.related}>
            {file.related.every((g) => g.items.length === 0) ? (
              <div className={s.empty}>Nothing linked yet.</div>
            ) : (
              file.related.map((g) => (
                <div key={g.label} className={styles.relGroup}>
                  <div className={styles.relLabel}>{g.label}</div>
                  {g.items.length === 0 ? (
                    <div className={styles.relEmpty}>None</div>
                  ) : (
                    g.items.map((it) => (
                      <Link key={it.id} href={`/w/${slug}/crm/${ENTITY_PATH[it.entity]}/${it.id}`} className={styles.relItem}>
                        <Icon name={it.entity === "contact" ? "user" : it.entity === "deal" ? "crm" : "globe"} size={14} />
                        <span className={styles.relName}>{it.name}</span>
                        {it.meta && <DataChip>{it.meta}</DataChip>}
                        <Icon name="link" size={12} />
                      </Link>
                    ))
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {tab === "documents" && (
          <div className={styles.docs}>
            {canEdit && file.entity !== "contact" && (
              <DropZone
                workspaceId={workspaceId}
                scope={file.entity === "deal" ? { dealId: file.recordId } : { accountId: file.recordId }}
                onDone={() => router.refresh()}
              />
            )}
            {file.documents.length === 0 ? (
              <div className={s.empty}>
                {file.entity === "contact"
                  ? "Documents attach to accounts and deals."
                  : "No documents yet. Drag files above — they’re stored, displayed, and (for docs) indexed for the agents."}
              </div>
            ) : (
              <div className={styles.attachGrid}>
                {file.documents.map((d) => (
                  <Attachment
                    key={d.id}
                    item={{ id: d.id, name: d.name, mime: d.mime, url: d.blobUrl /* already the access-controlled inline proxy URL (listDocumentsForRecord) */, downloadUrl: `/api/workspaces/${workspaceId}/documents/${d.id}/download` }}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {tab === "memories" && (
          <div className={styles.mems}>
            {file.memories.length === 0 ? (
              <div className={s.empty}>No knowledge-graph memories about this {file.entity} yet.</div>
            ) : (
              file.memories.map((m, i) => (
                <div key={i} className={styles.mem}>
                  <div className={styles.memBody}>{m.content}</div>
                  <span className={styles.memTier}>
                    {m.trustTier} · {m.confidence}%
                  </span>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Overview (view + inline edit) ────────────────────────────────────────────

function Overview({
  file,
  base,
  canEdit,
  canManageFields,
  slug,
  onSaved,
}: {
  file: RecordFileData;
  base: string;
  canEdit: boolean;
  canManageFields: boolean;
  slug: string;
  onSaved: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [std, setStd] = useState<Record<string, string>>(() => stdInitial(file));
  const [vals, setVals] = useState<Record<string, string>>(() =>
    Object.fromEntries(file.fields.map((f) => [f.def.id, f.value ?? ""])),
  );

  async function save() {
    setSaving(true);
    try {
      // Standard fields.
      const patch = stdPatch(file, std);
      if (Object.keys(patch).length > 0) {
        await fetch(base, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(patch) });
      }
      // Custom fields that changed.
      for (const f of file.fields) {
        const next = vals[f.def.id] ?? "";
        if (next !== (f.value ?? "")) {
          await fetch(`${base}/fields`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ fieldId: f.def.id, value: next }),
          });
        }
      }
      setEditing(false);
      onSaved();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className={styles.overviewBar}>
        {canManageFields && (
          <Link href={`/w/${slug}/settings/crm-fields`} className={styles.manageLink}>
            <Icon name="settings" size={13} /> Manage fields
          </Link>
        )}
        {canEdit &&
          (editing ? (
            <span className={styles.editActions}>
              <Btn variant="quiet" size="sm" onClick={() => { setEditing(false); setStd(stdInitial(file)); setVals(Object.fromEntries(file.fields.map((f) => [f.def.id, f.value ?? ""]))); }}>
                Cancel
              </Btn>
              <Btn variant="primary" size="sm" onClick={save} disabled={saving}>
                {saving ? "Saving…" : "Save"}
              </Btn>
            </span>
          ) : (
            <Btn variant="ghost" size="sm" icon="settings" onClick={() => setEditing(true)}>
              Edit
            </Btn>
          ))}
      </div>

      <div className={styles.fields}>
        {/* Standard fields (editable in edit mode) */}
        {stdFields(file).map((sf) => (
          <div key={sf.key} className={styles.fieldRow}>
            <div className={styles.fieldLabel}>{sf.label}</div>
            {editing ? (
              <input
                className={styles.input}
                type={sf.numeric ? "number" : "text"}
                value={std[sf.key] ?? ""}
                onChange={(e) => setStd((p) => ({ ...p, [sf.key]: e.target.value }))}
              />
            ) : (
              <div className={styles.fieldValue}>{sf.display || "—"}</div>
            )}
          </div>
        ))}

        {file.fields.length === 0 && !canManageFields && (
          <div className={s.empty}>No custom fields defined yet.</div>
        )}
        {file.fields.map((f) => (
          <div key={f.def.id} className={styles.fieldRow}>
            <div className={styles.fieldLabel}>{f.def.label}{f.def.sensitive && <span className={styles.lockIc}><Icon name="lock" size={10} /></span>}</div>
            {editing ? (
              <FieldInput def={f.def} value={vals[f.def.id] ?? ""} onChange={(v) => setVals((p) => ({ ...p, [f.def.id]: v }))} />
            ) : (
              <div className={styles.fieldValue}>{displayField(f)}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function stdInitial(file: RecordFileData): Record<string, string> {
  const e = file.editable;
  if (file.entity === "account") return { name: e.name, domain: e.domain ?? "" };
  if (file.entity === "deal") return { name: e.name, value: e.valueMinor != null ? String(e.valueMinor / 100) : "" };
  return { name: e.name, title: e.title ?? "" };
}

function stdFields(file: RecordFileData): { key: string; label: string; display: string; numeric?: boolean }[] {
  const e = file.editable;
  if (file.entity === "account") return [
    { key: "name", label: "Name", display: e.name },
    { key: "domain", label: "Domain", display: e.domain ?? "" },
  ];
  if (file.entity === "deal") return [
    { key: "name", label: "Name", display: e.name },
    { key: "value", label: "Value (USD)", display: e.valueMinor != null ? String(e.valueMinor / 100) : "", numeric: true },
  ];
  return [
    { key: "name", label: "Name", display: e.name },
    { key: "title", label: "Title", display: e.title ?? "" },
  ];
}

function stdPatch(file: RecordFileData, std: Record<string, string>): Record<string, unknown> {
  const init = stdInitial(file);
  const patch: Record<string, unknown> = {};
  if (std.name !== undefined && std.name !== init.name) patch.name = std.name;
  if (file.entity === "account" && std.domain !== init.domain) patch.domain = std.domain;
  if (file.entity === "contact" && std.title !== init.title) patch.title = std.title;
  if (file.entity === "deal" && std.value !== init.value) patch.valueMinor = Math.round((Number(std.value) || 0) * 100);
  return patch;
}

// ── Field input by type ──────────────────────────────────────────────────────

function FieldInput({ def, value, onChange }: { def: FieldDef; value: string; onChange: (v: string) => void }) {
  if (def.type === "longtext") {
    return <textarea className={styles.input} rows={3} value={value} onChange={(e) => onChange(e.target.value)} />;
  }
  if (def.type === "boolean") {
    return (
      <select className={styles.input} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">—</option>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    );
  }
  if (def.type === "select") {
    return (
      <select className={styles.input} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">—</option>
        {def.options.map((o) => (
          <option key={o.key} value={o.key}>{o.label}</option>
        ))}
      </select>
    );
  }
  if (def.type === "multiselect") {
    const selected = new Set(value.split(",").map((k) => k.trim()).filter(Boolean));
    return (
      <div className={styles.checks}>
        {def.options.map((o) => (
          <label key={o.key} className={styles.check}>
            <input
              type="checkbox"
              checked={selected.has(o.key)}
              onChange={(e) => {
                const next = new Set(selected);
                if (e.target.checked) next.add(o.key);
                else next.delete(o.key);
                onChange(Array.from(next).join(","));
              }}
            />
            {o.label}
          </label>
        ))}
      </div>
    );
  }
  const inputType = def.type === "number" || def.type === "currency" ? "number" : def.type === "date" ? "date" : "text";
  return <input className={styles.input} type={inputType} value={value} onChange={(e) => onChange(e.target.value)} />;
}

// ── Notes composer ───────────────────────────────────────────────────────────

function NoteComposer({ base, onAdded }: { base: string; onAdded: () => void }) {
  const [type, setType] = useState<CrmNoteType>("note");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);

  async function add() {
    if (!body.trim() || busy) return;
    setBusy(true);
    const r = await fetch(`${base}/notes`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type, title: title.trim() || undefined, body: body.trim() }),
    });
    setBusy(false);
    if (r.ok) {
      setTitle("");
      setBody("");
      onAdded();
    }
  }

  return (
    <div className={styles.composer}>
      <div className={styles.composerRow}>
        <select className={styles.input} value={type} onChange={(e) => setType(e.target.value as CrmNoteType)}>
          {CRM_NOTE_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input className={styles.input} placeholder="Title (optional)" value={title} onChange={(e) => setTitle(e.target.value)} />
      </div>
      <textarea className={styles.input} rows={2} placeholder="Add a note or journal entry…" value={body} onChange={(e) => setBody(e.target.value)} />
      <div className={styles.composerActions}>
        <Btn variant="primary" size="sm" icon="send" onClick={add} disabled={busy || !body.trim()}>
          {busy ? "…" : "Add entry"}
        </Btn>
      </div>
    </div>
  );
}

// ── Tags ─────────────────────────────────────────────────────────────────────

function TagRow({ file, base, canEdit, onChange }: { file: RecordFileData; base: string; canEdit: boolean; onChange: () => void }) {
  const [adding, setAdding] = useState(false);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);

  async function add() {
    if (!label.trim() || busy) return;
    setBusy(true);
    const r = await fetch(`${base}/tags`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ label: label.trim() }) });
    setBusy(false);
    if (r.ok) { setLabel(""); setAdding(false); onChange(); }
  }
  async function remove(tagId: string) {
    await fetch(`${base}/tags`, { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ tagId }) });
    onChange();
  }

  if (file.tags.length === 0 && !canEdit) return null;
  return (
    <div className={styles.tags}>
      {file.tags.map((t) => (
        <span key={t.id} className={styles.tag} style={t.color ? { background: t.color } : undefined}>
          {t.label}
          {canEdit && (
            <button className={styles.tagX} onClick={() => remove(t.id)} aria-label={`Remove ${t.label}`}>
              <Icon name="x" size={10} />
            </button>
          )}
        </span>
      ))}
      {canEdit &&
        (adding ? (
          <span className={styles.tagAdd}>
            <input
              className={styles.tagInput}
              value={label}
              autoFocus
              placeholder="tag"
              onChange={(e) => setLabel(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") add(); if (e.key === "Escape") setAdding(false); }}
            />
          </span>
        ) : (
          <button className={styles.tagAddBtn} onClick={() => setAdding(true)}>
            <Icon name="plus" size={11} /> tag
          </button>
        ))}
    </div>
  );
}
