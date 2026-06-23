"use client";

/**
 * Settings → CRM fields (COMMS-CRM-DEPTH §6, admin). Define the custom-field engine
 * per entity: add fields, edit labels, toggle enabled, delete (drops values), and set
 * select options. These defs drive the record-file forms, the L0 columns, AND the
 * agents' dynamic tool schemas (CRM-D3).
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Btn, Icon } from "@/components/primitives";
import type { FieldDef } from "@/lib/domain/crm-fields";
import { CRM_ENTITIES, CRM_FIELD_TYPES, type CrmEntity, type CrmFieldType } from "@/lib/domain/crm-enums";
import s from "@/components/common/screen.module.css";
import styles from "./CrmFieldsManager.module.css";

export type ManagerFields = Record<CrmEntity, FieldDef[]>;

const ENTITY_LABEL: Record<CrmEntity, string> = { account: "Accounts", deal: "Deals", contact: "Contacts" };
const NEEDS_OPTIONS = (t: CrmFieldType) => t === "select" || t === "multiselect";

export function CrmFieldsManager({ workspaceId, backHref, fields }: { workspaceId: string; backHref: string; fields: ManagerFields }) {
  const router = useRouter();
  const api = `/api/workspaces/${workspaceId}/crm/fields`;

  async function toggle(fieldId: string, enabled: boolean) {
    await fetch(`${api}/${fieldId}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled }) });
    router.refresh();
  }
  async function remove(fieldId: string) {
    if (!confirm("Delete this field and all its stored values? This cannot be undone.")) return;
    await fetch(`${api}/${fieldId}`, { method: "DELETE" });
    router.refresh();
  }

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <Link href={backHref} className={styles.back}><Icon name="anchor" size={13} /> Settings</Link>
          <h1 className={s.title}>CRM fields</h1>
        </div>
      </header>
      <p className={styles.note}>
        Fields you define here appear on every record’s Overview, in the CRM column chooser, and in what the
        agents can read and (with approval) write. Free-text fields are encrypted; controlled types stay
        queryable.
      </p>

      {CRM_ENTITIES.map((entity) => (
        <section key={entity} className={styles.section}>
          <div className={styles.sectionHead}>{ENTITY_LABEL[entity]}</div>
          <div className={styles.list}>
            {fields[entity].length === 0 && <div className={styles.empty}>No fields yet.</div>}
            {fields[entity].map((f) => (
              <div key={f.id} className={`${styles.row} ${f.enabled ? "" : styles.disabled}`}>
                <span className={styles.fLabel}>{f.label}</span>
                <span className={styles.fKey}>{f.key}</span>
                <span className={styles.fType}>{f.type}</span>
                {f.sensitive && <span className={styles.fLock}><Icon name="lock" size={11} /> encrypted</span>}
                <span className={styles.rowActions}>
                  <button className={styles.linkBtn} onClick={() => toggle(f.id, !f.enabled)}>{f.enabled ? "Disable" : "Enable"}</button>
                  <button className={`${styles.linkBtn} ${styles.danger}`} onClick={() => remove(f.id)}>Delete</button>
                </span>
              </div>
            ))}
          </div>
          <AddField api={api} entity={entity} onAdded={() => router.refresh()} />
        </section>
      ))}
    </div>
  );
}

function AddField({ api, entity, onAdded }: { api: string; entity: CrmEntity; onAdded: () => void }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [type, setType] = useState<CrmFieldType>("text");
  const [options, setOptions] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function keyFromLabel(l: string): string {
    return l.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60);
  }

  async function add() {
    const key = keyFromLabel(label);
    if (!label.trim() || !key || busy) return;
    setBusy(true);
    setError(null);
    const opts = NEEDS_OPTIONS(type)
      ? options.split(",").map((o) => o.trim()).filter(Boolean).map((l) => ({ key: keyFromLabel(l), label: l }))
      : undefined;
    const r = await fetch(api, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ entity, key, label: label.trim(), type, options: opts }),
    });
    setBusy(false);
    if (r.ok) {
      setLabel(""); setOptions(""); setType("text"); setOpen(false);
      onAdded();
    } else {
      setError(r.status === 409 ? "A field with that key already exists." : "Couldn't add the field.");
    }
  }

  if (!open) {
    return (
      <button className={styles.addBtn} onClick={() => setOpen(true)}>
        <Icon name="plus" size={12} /> Add field
      </button>
    );
  }
  return (
    <div className={styles.addForm}>
      <input className={styles.input} placeholder="Field label (e.g. Region)" value={label} onChange={(e) => setLabel(e.target.value)} autoFocus />
      <select className={styles.input} value={type} onChange={(e) => setType(e.target.value as CrmFieldType)}>
        {CRM_FIELD_TYPES.map((t) => (
          <option key={t} value={t}>{t}</option>
        ))}
      </select>
      {NEEDS_OPTIONS(type) && (
        <input className={styles.input} placeholder="Options, comma-separated" value={options} onChange={(e) => setOptions(e.target.value)} />
      )}
      <Btn variant="primary" size="sm" onClick={add} disabled={busy || !label.trim()}>Add</Btn>
      <Btn variant="quiet" size="sm" onClick={() => setOpen(false)}>Cancel</Btn>
      {error && <span className={styles.err}>{error}</span>}
    </div>
  );
}
