"use client";

/**
 * CRM record FILE (COMMS-CRM-DEPTH §6, L1) — the deep, clickable view of one
 * account/deal/contact. Read-only in CRM-D1: Overview (standard stats + dynamic custom
 * fields), Notes/Journal, Activity, Related (clickable into sub-records), Documents,
 * and trust-tiered Memories. Editing + adding notes land in CRM-D2/D3.
 */
import { useState } from "react";
import Link from "next/link";
import { Avatar, Icon, SurfBadge, DataChip } from "@/components/primitives";
import type { RecordFile as RecordFileData } from "@/lib/domain/crm-file";
import type { FieldWithValue } from "@/lib/domain/crm-fields";
import type { CrmEntity } from "@/lib/domain/crm-enums";
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
    const keys = value.split(",").map((k) => k.trim());
    return keys.map((k) => def.options.find((o) => o.key === k)?.label ?? k).join(", ");
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
  backHref,
}: {
  file: RecordFileData;
  slug: string;
  backHref: string;
}) {
  const [tab, setTab] = useState<Tab>("overview");

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
          <Link href={`/w/${slug}/agents`} className={styles.askLink}>
            <Icon name="agents" size={13} /> Ask an agent about this {file.entity}
          </Link>
        </div>
        <div className={styles.headMain}>
          <Avatar name={file.title} size="lg" />
          <div className={styles.headText}>
            <h1 className={styles.title}>{file.title}</h1>
            {file.subtitle && <div className={styles.subtitle}>{file.subtitle}</div>}
            {file.tags.length > 0 && (
              <div className={styles.tags}>
                {file.tags.map((t) => (
                  <span key={t.id} className={styles.tag} style={t.color ? { background: t.color } : undefined}>
                    {t.label}
                  </span>
                ))}
              </div>
            )}
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
          <div className={styles.fields}>
            {file.fields.length === 0 ? (
              <div className={s.empty}>No custom fields defined. Admins can add fields in Settings → CRM fields.</div>
            ) : (
              file.fields.map((f) => (
                <div key={f.def.id} className={styles.fieldRow}>
                  <div className={styles.fieldLabel}>{f.def.label}</div>
                  <div className={styles.fieldValue}>{displayField(f)}</div>
                </div>
              ))
            )}
          </div>
        )}

        {tab === "notes" && (
          <div className={styles.notes}>
            {file.notes.length === 0 ? (
              <div className={s.empty}>No notes or journal entries yet. Adding entries lands in the next sprint.</div>
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
            {file.documents.length === 0 ? (
              <div className={s.empty}>No documents attached. Upload + RAG lands in a later sprint.</div>
            ) : (
              file.documents.map((d) => (
                <a key={d.id} href={d.blobUrl} target="_blank" rel="noreferrer" className={styles.doc}>
                  <Icon name="paperclip" size={14} /> <span className={styles.docName}>{d.name}</span>
                  {d.mime && <span className={styles.docMime}>{d.mime}</span>}
                </a>
              ))
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
