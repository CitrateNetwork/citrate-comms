"use client";

/**
 * Persona editor (S5). Owner/Admin edit a persona's prompt layers (1–4), agentile
 * skills, model tier, step/temperature budget, and tool allow-list. The force-included
 * guardrails layer is shown READ-ONLY (it can never be removed). Export to JSON.
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Btn, Icon, SurfBadge } from "@/components/primitives";
import { PROMPT_LAYERS } from "@/lib/ai/personas";
import type { PersonaConfig } from "@/lib/domain/personas";
import s from "@/components/common/screen.module.css";
import styles from "./PersonaEditor.module.css";

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

      {/* Guardrails (read-only) */}
      <section className={styles.section}>
        <div className={styles.sectionHead}>Guardrails <SurfBadge variant="outline">always on · read-only</SurfBadge></div>
        <pre className={styles.guardrails}>{config.guardrails}</pre>
      </section>
    </div>
  );
}
