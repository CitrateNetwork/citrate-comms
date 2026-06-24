"use client";

/**
 * Settings → Agents (S5). Owner/Admin list of personas: edit (→ editor), clone, delete
 * (custom only; templates protected), and import from JSON. The org-default templates
 * are marked; clones/imports are fully editable.
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Btn, Icon, SurfBadge } from "@/components/primitives";
import s from "@/components/common/screen.module.css";
import styles from "./PersonaManager.module.css";

export interface UiPersonaRow {
  id: string;
  name: string;
  baseTemplate: string;
  isTemplate: boolean;
  enabled: boolean;
  toolCount: number;
}

export interface UiMemberOpt {
  sub: string;
  name: string;
}
export interface UiGrant {
  id: string;
  granteeSub: string;
  granteeName: string | null;
  personaId: string | null;
}

export function PersonaManager({
  workspaceId,
  backHref,
  personas,
  canDelegate = false,
  members = [],
  grants: initialGrants = [],
}: {
  workspaceId: string;
  backHref: string;
  personas: UiPersonaRow[];
  canDelegate?: boolean;
  members?: UiMemberOpt[];
  grants?: UiGrant[];
}) {
  const router = useRouter();
  const api = `/api/workspaces/${workspaceId}/personas`;
  const grantsApi = `/api/workspaces/${workspaceId}/persona-config-grants`;
  const [busy, setBusy] = useState(false);

  // CFG delegation state (admin only).
  const [grants, setGrants] = useState<UiGrant[]>(initialGrants);
  const [grantee, setGrantee] = useState("");
  const [grantPersona, setGrantPersona] = useState(""); // "" = all personas
  const personaName = (id: string | null) => (id ? personas.find((p) => p.id === id)?.name ?? "a persona" : "All personas");

  async function addGrant() {
    if (!grantee) return;
    const r = await fetch(grantsApi, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ granteeSub: grantee, personaId: grantPersona || null }),
    });
    if (r.ok) {
      const member = members.find((m) => m.sub === grantee);
      // Optimistic add; refresh pulls the authoritative list (with dedupe).
      setGrants((prev) => [
        ...prev.filter((g) => !(g.granteeSub === grantee && g.personaId === (grantPersona || null))),
        { id: `tmp-${grantee}-${grantPersona}`, granteeSub: grantee, granteeName: member?.name ?? null, personaId: grantPersona || null },
      ]);
      setGrantee("");
      setGrantPersona("");
      router.refresh();
    }
  }
  async function revokeGrant(id: string) {
    setGrants((prev) => prev.filter((g) => g.id !== id));
    await fetch(`${grantsApi}/${id}`, { method: "DELETE" });
  }

  async function clone(id: string, name: string) {
    const n = prompt("Name for the cloned persona:", `${name} (copy)`);
    if (!n?.trim()) return;
    await fetch(`${api}/${id}/clone`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: n.trim() }) });
    router.refresh();
  }
  async function del(id: string) {
    if (!confirm("Delete this persona? This can't be undone.")) return;
    const r = await fetch(`${api}/${id}`, { method: "DELETE" });
    if (!r.ok) alert("Templates can't be deleted; clone one to customize instead.");
    router.refresh();
  }
  async function importJson() {
    const raw = prompt("Paste an exported persona JSON:");
    if (!raw?.trim()) return;
    setBusy(true);
    try {
      const data = JSON.parse(raw);
      const r = await fetch(`${api}/import`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });
      if (!r.ok) alert("Import failed — check the JSON shape.");
      router.refresh();
    } catch {
      alert("That isn't valid JSON.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <Link href={backHref} className={styles.back}><Icon name="anchor" size={13} /> Settings</Link>
          <h1 className={s.title}>Agents</h1>
        </div>
        <Btn variant="ghost" icon="download" onClick={importJson} disabled={busy}>Import persona</Btn>
      </header>
      <p className={styles.note}>
        Customize each persona’s prompt, skills, model, and tools. The org-default templates are protected —
        clone one to make an editable variant. A force-included guardrails layer is always applied and can’t
        be removed.
      </p>

      <div className={styles.grid}>
        {personas.map((p) => (
          <div key={p.id} className={styles.card}>
            <div className={styles.cardHead}>
              <span className={styles.name}>{p.name}</span>
              {p.isTemplate && <SurfBadge variant="outline">template</SurfBadge>}
              {!p.enabled && <SurfBadge variant="outline">disabled</SurfBadge>}
            </div>
            <div className={styles.meta}>{p.baseTemplate} · {p.toolCount} tools</div>
            <div className={styles.actions}>
              <Link href={`./agents/${p.id}`} className={styles.editLink}><Icon name="settings" size={13} /> Edit</Link>
              <button className={styles.linkBtn} onClick={() => clone(p.id, p.name)}>Clone</button>
              {!p.isTemplate && <button className={`${styles.linkBtn} ${styles.danger}`} onClick={() => del(p.id)}>Delete</button>}
            </div>
          </div>
        ))}
      </div>

      {canDelegate && (
        <section className={styles.delegate}>
          <div className={styles.delegateHead}>Config delegation</div>
          <p className={styles.note}>
            Let a teammate configure a persona’s prompts, skills, resources, and settings without making them a
            workspace admin. They can’t delete personas or change membership. Grants are audited.
          </p>
          <div className={styles.grantForm}>
            <select className={styles.grantSelect} value={grantee} onChange={(e) => setGrantee(e.target.value)} aria-label="Member">
              <option value="">Choose a member…</option>
              {members.map((m) => (
                <option key={m.sub} value={m.sub}>{m.name}</option>
              ))}
            </select>
            <select className={styles.grantSelect} value={grantPersona} onChange={(e) => setGrantPersona(e.target.value)} aria-label="Persona">
              <option value="">All personas</option>
              {personas.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <Btn variant="primary" size="sm" onClick={addGrant} disabled={!grantee}>Grant</Btn>
          </div>
          {grants.length > 0 && (
            <div className={styles.grantList}>
              {grants.map((g) => (
                <div key={g.id} className={styles.grantItem}>
                  <span className={styles.grantWho}>{g.granteeName ?? g.granteeSub.slice(0, 10)}</span>
                  <span className={styles.grantScope}>can configure <strong>{personaName(g.personaId)}</strong></span>
                  <button className={`${styles.linkBtn} ${styles.danger}`} onClick={() => revokeGrant(g.id)}>Revoke</button>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
