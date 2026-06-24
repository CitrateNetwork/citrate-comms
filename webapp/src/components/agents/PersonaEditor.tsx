"use client";

/**
 * Persona editor (S5). Owner/Admin edit a persona's prompt layers (1–4), agentile
 * skills, model tier, step/temperature budget, and tool allow-list. The force-included
 * guardrails layer is shown READ-ONLY (it can never be removed). Export to JSON.
 */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Btn, Icon, SurfBadge } from "@/components/primitives";
import { PROMPT_LAYERS } from "@/lib/ai/personas";
import type { PersonaConfig } from "@/lib/domain/personas";
import s from "@/components/common/screen.module.css";
import styles from "./PersonaEditor.module.css";

interface ResourceItem {
  id: string;
  kind: "text" | "link" | "document";
  title: string;
  content: string | null;
  url: string | null;
  enabled: boolean;
}

export function PersonaEditor({ workspaceId, backHref, config }: { workspaceId: string; backHref: string; config: PersonaConfig }) {
  const router = useRouter();
  const api = `/api/workspaces/${workspaceId}/personas/${config.id}`;

  const [name, setName] = useState(config.name);
  const [gateway, setGateway] = useState(config.model.gateway);
  const [frontier, setFrontier] = useState(config.model.frontier);
  const [preferFrontier, setPreferFrontier] = useState(config.model.preferFrontier);
  const [maxSteps, setMaxSteps] = useState(config.maxSteps);
  const [temperature, setTemperature] = useState(config.temperature);
  const [enabled, setEnabled] = useState(config.enabled);
  const [tools, setTools] = useState<Set<string>>(new Set(config.tools));
  const [layers, setLayers] = useState<Record<number, string>>(() => {
    const m: Record<number, string> = { 1: "", 2: "", 3: "", 4: "" };
    for (const l of config.layers) m[l.layer] = l.content;
    return m;
  });
  const [skills, setSkills] = useState(config.skills);
  const [savingSettings, setSavingSettings] = useState(false);
  const [savedNote, setSavedNote] = useState<string | null>(null);

  // CFG: pinned resources/knowledge.
  const [resources, setResources] = useState<ResourceItem[]>([]);
  const [resKind, setResKind] = useState<"text" | "link">("text");
  const [resTitle, setResTitle] = useState("");
  const [resBody, setResBody] = useState("");
  const [addingRes, setAddingRes] = useState(false);

  const loadResources = useCallback(async () => {
    const r = await fetch(`${api}/resources`);
    if (r.ok) {
      const j = (await r.json()) as { resources: ResourceItem[] };
      setResources(j.resources ?? []);
    }
  }, [api]);
  useEffect(() => {
    void loadResources();
  }, [loadResources]);

  async function addResource() {
    const title = resTitle.trim();
    const value = resBody.trim();
    if (!title || !value || addingRes) return;
    setAddingRes(true);
    const payload = resKind === "text" ? { kind: "text", title, content: value } : { kind: "link", title, url: value };
    const r = await fetch(`${api}/resources`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    setAddingRes(false);
    if (r.ok) {
      setResTitle("");
      setResBody("");
      void loadResources();
    } else {
      setSavedNote(resKind === "link" ? "Add failed — link must start with http(s)." : "Add failed.");
    }
  }

  async function toggleResource(id: string, enabled: boolean) {
    setResources((prev) => prev.map((x) => (x.id === id ? { ...x, enabled } : x)));
    await fetch(`${api}/resources/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled }) });
  }

  async function deleteResource(id: string) {
    setResources((prev) => prev.filter((x) => x.id !== id));
    await fetch(`${api}/resources/${id}`, { method: "DELETE" });
  }

  function toggleTool(t: string) {
    setTools((prev) => {
      const n = new Set(prev);
      if (n.has(t)) n.delete(t);
      else n.add(t);
      return n;
    });
  }

  async function saveSettings() {
    setSavingSettings(true);
    setSavedNote(null);
    const r = await fetch(api, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, model: { gateway, frontier, preferFrontier }, tools: Array.from(tools), maxSteps, temperature, enabled }),
    });
    setSavingSettings(false);
    setSavedNote(r.ok ? "Saved." : "Save failed.");
    if (r.ok) router.refresh();
  }

  async function saveLayer(layer: number) {
    const r = await fetch(`${api}/prompts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ layer, content: layers[layer] ?? "" }),
    });
    setSavedNote(r.ok ? `Layer ${layer} saved.` : "Save failed.");
  }

  async function toggleSkill(key: string, next: boolean) {
    setSkills((prev) => prev.map((sk) => (sk.key === key ? { ...sk, enabled: next } : sk)));
    await fetch(`${api}/skills`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ skillKey: key, enabled: next }) });
  }

  async function exportPersona() {
    const r = await fetch(`${api}?export=1`);
    if (!r.ok) return;
    const { persona } = await r.json();
    const blob = new Blob([JSON.stringify(persona, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${config.key}.persona.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className={s.wrap}>
      <header className={styles.head}>
        <div className={styles.headTop}>
          <Link href={backHref} className={styles.back}><Icon name="anchor" size={13} /> Agents</Link>
          <div className={styles.headActions}>
            {config.isTemplate && <SurfBadge variant="outline">template</SurfBadge>}
            {savedNote && <span className={styles.savedNote}>{savedNote}</span>}
            <Btn variant="ghost" size="sm" icon="download" onClick={exportPersona}>Export</Btn>
          </div>
        </div>
        <h1 className={s.title}>{config.name}</h1>
      </header>

      {/* Settings */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Settings</div>
        <div className={styles.grid2}>
          <label className={styles.field}><span className={styles.lbl}>Name</span><input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label className={styles.field}><span className={styles.lbl}>Enabled</span>
            <select className={styles.input} value={enabled ? "1" : "0"} onChange={(e) => setEnabled(e.target.value === "1")}><option value="1">Enabled</option><option value="0">Disabled</option></select>
          </label>
          <label className={styles.field}><span className={styles.lbl}>Gateway model (blank = deployment default)</span><input className={styles.input} value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder="(default)" /></label>
          <label className={styles.field}><span className={styles.lbl}>Frontier model (heavier route, optional)</span><input className={styles.input} value={frontier} onChange={(e) => setFrontier(e.target.value)} placeholder="(deployment frontier)" /></label>
          <label className={styles.field}><span className={styles.lbl}>Prefer frontier for heavy tasks</span>
            <select className={styles.input} value={preferFrontier ? "1" : "0"} onChange={(e) => setPreferFrontier(e.target.value === "1")}><option value="0">No</option><option value="1">Yes</option></select>
          </label>
          <label className={styles.field}><span className={styles.lbl}>Max tool steps ({maxSteps})</span><input className={styles.input} type="range" min={1} max={20} value={maxSteps} onChange={(e) => setMaxSteps(Number(e.target.value))} /></label>
          <label className={styles.field}><span className={styles.lbl}>Temperature ({temperature.toFixed(2)})</span><input className={styles.input} type="range" min={0} max={1} step={0.05} value={temperature} onChange={(e) => setTemperature(Number(e.target.value))} /></label>
        </div>
        <div className={styles.saveRow}><Btn variant="primary" size="sm" onClick={saveSettings} disabled={savingSettings}>{savingSettings ? "Saving…" : "Save settings"}</Btn></div>
      </section>

      {/* Tools */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Tools (allow-list)</div>
        <div className={styles.tools}>
          {config.allTools.map((t) => (
            <label key={t} className={styles.tool}>
              <input type="checkbox" checked={tools.has(t)} onChange={() => toggleTool(t)} /> {t}
            </label>
          ))}
        </div>
        <div className={styles.hint}>Save settings to apply tool changes.</div>
      </section>

      {/* Prompt layers */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Prompt layers</div>
        {PROMPT_LAYERS.map((pl) => (
          <div key={pl.layer} className={styles.layer}>
            <div className={styles.layerHead}>
              <span className={styles.layerLabel}>{pl.label}</span>
              <span className={styles.layerHelp}>{pl.help}</span>
            </div>
            <textarea
              className={styles.textarea}
              rows={pl.layer === 1 ? 5 : 3}
              value={layers[pl.layer] ?? ""}
              placeholder={pl.layer === 1 ? config.missionDefault : "(blank = default)"}
              onChange={(e) => setLayers((m) => ({ ...m, [pl.layer]: e.target.value }))}
            />
            <div className={styles.saveRow}><Btn variant="ghost" size="sm" onClick={() => saveLayer(pl.layer)}>Save layer</Btn></div>
          </div>
        ))}
      </section>

      {/* Skills */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Agentile skills</div>
        {skills.map((sk) => (
          <label key={sk.key} className={styles.skill}>
            <input type="checkbox" checked={sk.enabled} onChange={(e) => toggleSkill(sk.key, e.target.checked)} />
            <span><strong>{sk.key}</strong> — {sk.fragment}</span>
          </label>
        ))}
      </section>

      {/* Resources & knowledge (CFG) */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Resources &amp; knowledge</div>
        <div className={styles.hint}>
          Pin org material this agent should treat as authoritative. Enabled items are folded into its system
          prompt every turn. Text is encrypted at rest; links are read on demand with web.fetch.
        </div>
        {resources.length > 0 && (
          <div className={styles.resList}>
            {resources.map((r) => (
              <div key={r.id} className={styles.resItem}>
                <label className={styles.resToggle}>
                  <input type="checkbox" checked={r.enabled} onChange={(e) => toggleResource(r.id, e.target.checked)} />
                </label>
                <div className={styles.resBody}>
                  <div className={styles.resTitle}>
                    <SurfBadge variant="outline">{r.kind}</SurfBadge> {r.title}
                  </div>
                  {r.kind === "link" && r.url && <a className={styles.resUrl} href={r.url} target="_blank" rel="noreferrer">{r.url}</a>}
                  {r.kind === "text" && r.content && <div className={styles.resText}>{r.content}</div>}
                </div>
                <button className={styles.resDel} onClick={() => deleteResource(r.id)} aria-label="Delete resource">
                  <Icon name="x" size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
        <div className={styles.resAdd}>
          <div className={styles.resAddRow}>
            <select className={styles.resKind} value={resKind} onChange={(e) => setResKind(e.target.value as "text" | "link")}>
              <option value="text">Knowledge text</option>
              <option value="link">Reference link</option>
            </select>
            <input className={styles.input} value={resTitle} onChange={(e) => setResTitle(e.target.value)} placeholder="Title (e.g. Pricing policy)" />
          </div>
          {resKind === "text" ? (
            <textarea className={styles.textarea} rows={3} value={resBody} onChange={(e) => setResBody(e.target.value)} placeholder="Paste the knowledge the agent should know…" />
          ) : (
            <input className={styles.input} value={resBody} onChange={(e) => setResBody(e.target.value)} placeholder="https://…" />
          )}
          <div className={styles.saveRow}>
            <Btn variant="primary" size="sm" onClick={addResource} disabled={addingRes || !resTitle.trim() || !resBody.trim()}>
              {addingRes ? "Adding…" : "Add resource"}
            </Btn>
          </div>
        </div>
      </section>

      {/* Guardrails (read-only) */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Guardrails <SurfBadge variant="outline">always on · read-only</SurfBadge></div>
        <pre className={styles.guardrails}>{config.guardrails}</pre>
      </section>
    </div>
  );
}
