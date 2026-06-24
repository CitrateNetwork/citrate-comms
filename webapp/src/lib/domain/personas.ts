/**
 * Persona repository (COMMS-AGENTS build-spec §3, §8). Personas are the agent BRAIN:
 * a layered prompt template + tool allow-list + model tier + skills. The three org
 * defaults (lib/ai/personas.ts) are SEEDED per workspace as `is_template` rows that
 * Owners/Admins clone and customize. Editable layers 1–4 live in `agent_prompts`
 * (encrypted); the force-included guardrails (layer 6) live in code and are never
 * stored — they cannot be removed.
 */
import { and, asc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agentPersonas, agentPrompts, agentSkills } from "@/lib/db/schema";
import { decryptField, encryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { GUARDRAILS } from "@/lib/ai/system-prompt";
import { resolvePersonaResources, type PersonaResourceForPrompt } from "@/lib/domain/agent-config";
import {
  DEFAULT_PERSONA_LIST,
  DEFAULT_PERSONAS,
  SKILL_FRAGMENTS,
  ALL_TOOL_NAMES,
  type PersonaKey,
  type PersonaModel,
  type SkillKey,
  type ToolName,
} from "@/lib/ai/personas";

const ALL_SKILL_KEYS = Object.keys(SKILL_FRAGMENTS) as SkillKey[];

function slugify(s: string): string {
  return s.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 50) || "persona";
}

export interface PersonaRow {
  id: string;
  key: string;
  name: string;
  baseTemplate: string;
  model: PersonaModel;
  tools: ToolName[];
  maxSteps: number;
  temperature: number; // 0..1
  enabled: boolean;
  isTemplate: boolean;
}

/** A persona ready for a chat turn: row + decrypted overrides + enabled skills. */
export interface ResolvedPersona extends PersonaRow {
  mission: string;
  preferFrontier: boolean;
  skills: SkillKey[];
  overrides: {
    mission?: string;
    capabilities?: string;
    workspaceKnowledge?: string;
    skills?: string;
  };
  /** CFG: pinned resources/knowledge folded into the system prompt at runtime. */
  resources: PersonaResourceForPrompt[];
}

interface StoredModel extends PersonaModel {
  preferFrontier?: boolean;
}

function toRow(r: typeof agentPersonas.$inferSelect): PersonaRow {
  const model = (r.modelJson as StoredModel) ?? { gateway: "" };
  return {
    id: r.id,
    key: r.key,
    name: r.name,
    baseTemplate: r.baseTemplate,
    model: { gateway: model.gateway ?? "", frontier: model.frontier },
    tools: (r.toolsJson as ToolName[]) ?? [],
    maxSteps: r.maxSteps,
    temperature: r.temperature / 100,
    enabled: r.enabled,
    isTemplate: r.isTemplate,
  };
}

/** Seed the three default persona templates for a workspace (idempotent on key). */
export async function seedDefaultPersonas(workspaceId: string, createdBy: string): Promise<number> {
  const existing = await db()
    .select({ key: agentPersonas.key })
    .from(agentPersonas)
    .where(eq(agentPersonas.workspaceId, workspaceId));
  const have = new Set(existing.map((e) => e.key));
  let seeded = 0;
  for (const t of DEFAULT_PERSONA_LIST) {
    if (have.has(t.key)) continue;
    const [row] = await db()
      .insert(agentPersonas)
      .values({
        workspaceId,
        key: t.key,
        name: t.name,
        baseTemplate: t.baseTemplate,
        modelJson: { gateway: t.model.gateway, frontier: t.model.frontier, preferFrontier: t.preferFrontier },
        toolsJson: t.tools,
        maxSteps: t.maxSteps,
        temperature: Math.round(t.temperature * 100),
        isTemplate: true,
        createdBy,
      })
      .returning({ id: agentPersonas.id });
    if (row) {
      await db()
        .insert(agentSkills)
        .values(t.skills.map((skillKey) => ({ workspaceId, personaId: row.id, skillKey, enabled: true })))
        .onConflictDoNothing();
    }
    seeded++;
  }
  // Keep the org TEMPLATE personas synced to the current defaults (every tool + the current
  // step budget). Only `isTemplate: true` rows are touched — user CLONES (isTemplate: false)
  // keep their customized tool list + budgets. To customize an agent, clone a template + edit.
  for (const t of DEFAULT_PERSONA_LIST) {
    await db()
      .update(agentPersonas)
      .set({ toolsJson: t.tools, maxSteps: t.maxSteps })
      .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.key, t.key), eq(agentPersonas.isTemplate, true)));
  }
  if (seeded > 0) {
    await appendAudit({ workspaceId, actorSub: createdBy, event: "personas_seeded", target: String(seeded) });
  }
  return seeded;
}

export async function listPersonas(workspaceId: string): Promise<PersonaRow[]> {
  const rows = await db()
    .select()
    .from(agentPersonas)
    .where(eq(agentPersonas.workspaceId, workspaceId))
    .orderBy(asc(agentPersonas.createdAt));
  return rows.map(toRow);
}

/**
 * MEN-1: which persona should an agent member use when called into a channel? Prefer the
 * persona explicitly bound to that agent (agentPersonas.agentId); otherwise fall back to the
 * first enabled, non-template persona in the workspace. Returns null if none are usable.
 */
export async function personaIdForAgent(workspaceId: string, agentId: string): Promise<string | null> {
  const [bound] = await db()
    .select({ id: agentPersonas.id })
    .from(agentPersonas)
    .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.agentId, agentId), eq(agentPersonas.enabled, true)))
    .limit(1);
  if (bound) return bound.id;
  const [fallback] = await db()
    .select({ id: agentPersonas.id })
    .from(agentPersonas)
    .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.enabled, true), eq(agentPersonas.isTemplate, false)))
    .orderBy(asc(agentPersonas.createdAt))
    .limit(1);
  return fallback?.id ?? null;
}

export async function getPersona(workspaceId: string, personaId: string): Promise<PersonaRow | null> {
  const [r] = await db()
    .select()
    .from(agentPersonas)
    .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId)))
    .limit(1);
  return r ? toRow(r) : null;
}

/** Resolve a persona for a chat turn: merge DB row + overrides + enabled skills,
 *  falling back to the code template (by baseTemplate) for the mission + skills. */
export async function resolvePersona(workspaceId: string, personaId: string): Promise<ResolvedPersona | null> {
  const [r] = await db()
    .select()
    .from(agentPersonas)
    .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId)))
    .limit(1);
  if (!r) return null;
  const row = toRow(r);
  const template = DEFAULT_PERSONAS[row.baseTemplate as PersonaKey];
  const storedModel = (r.modelJson as StoredModel) ?? { gateway: "" };

  // Editable layers 1–4 (decrypted) → overrides.
  const promptRows = await db()
    .select()
    .from(agentPrompts)
    .where(and(eq(agentPrompts.workspaceId, workspaceId), eq(agentPrompts.personaId, personaId)));
  const byLayer = new Map<number, string>();
  for (const p of promptRows) {
    try {
      byLayer.set(p.layer, decryptField(workspaceId, p.contentEnc));
    } catch {
      /* skip undecryptable */
    }
  }

  // Enabled skills (fall back to the template's set if none were stored).
  const skillRows = await db()
    .select({ skillKey: agentSkills.skillKey, enabled: agentSkills.enabled })
    .from(agentSkills)
    .where(and(eq(agentSkills.workspaceId, workspaceId), eq(agentSkills.personaId, personaId)));
  const enabledSkills = skillRows.filter((s) => s.enabled).map((s) => s.skillKey as SkillKey);
  const skills = enabledSkills.length > 0 ? enabledSkills : (template?.skills ?? []);

  const resources = await resolvePersonaResources(workspaceId, personaId);

  return {
    ...row,
    // Org TEMPLATE personas always expose the CURRENT full toolset at runtime, so newly-shipped
    // tools (e.g. crm.create) are available immediately without waiting for a sync write. Clones
    // (isTemplate=false) use their stored, customizable allow-list.
    tools: row.isTemplate ? ALL_TOOL_NAMES : row.tools,
    mission: byLayer.get(1) || template?.mission || `You are ${row.name}.`,
    preferFrontier: storedModel.preferFrontier ?? template?.preferFrontier ?? false,
    skills,
    overrides: {
      mission: byLayer.get(1),
      capabilities: byLayer.get(2),
      workspaceKnowledge: byLayer.get(3),
      skills: byLayer.get(4),
    },
    resources,
  };
}

// ── Customization (S5) ───────────────────────────────────────────────────────

export interface PersonaConfig {
  id: string;
  key: string;
  name: string;
  baseTemplate: string;
  model: { gateway: string; frontier: string; preferFrontier: boolean };
  tools: ToolName[];
  maxSteps: number;
  temperature: number; // 0..1
  enabled: boolean;
  isTemplate: boolean;
  missionDefault: string; // template mission (placeholder for layer 1)
  layers: { layer: number; content: string }[]; // current overrides (1–4), only those set
  skills: { key: SkillKey; fragment: string; enabled: boolean }[];
  allTools: ToolName[];
  guardrails: string; // read-only, force-included
}

/** Full editor config for one persona (decrypted overrides + skill toggles + defaults). */
export async function getPersonaConfig(workspaceId: string, personaId: string): Promise<PersonaConfig | null> {
  const [r] = await db()
    .select()
    .from(agentPersonas)
    .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId)))
    .limit(1);
  if (!r) return null;
  const row = toRow(r);
  const template = DEFAULT_PERSONAS[row.baseTemplate as PersonaKey];
  const storedModel = (r.modelJson as StoredModel) ?? { gateway: "" };

  const promptRows = await db()
    .select()
    .from(agentPrompts)
    .where(and(eq(agentPrompts.workspaceId, workspaceId), eq(agentPrompts.personaId, personaId)));
  const layers = promptRows
    .map((p) => {
      try {
        return { layer: p.layer, content: decryptField(workspaceId, p.contentEnc) };
      } catch {
        return null;
      }
    })
    .filter((x): x is { layer: number; content: string } => x !== null)
    .sort((a, b) => a.layer - b.layer);

  const skillRows = await db()
    .select({ skillKey: agentSkills.skillKey, enabled: agentSkills.enabled })
    .from(agentSkills)
    .where(and(eq(agentSkills.workspaceId, workspaceId), eq(agentSkills.personaId, personaId)));
  const skillState = new Map(skillRows.map((s) => [s.skillKey, s.enabled]));
  const skills = ALL_SKILL_KEYS.map((key) => ({
    key,
    fragment: SKILL_FRAGMENTS[key],
    enabled: skillState.has(key) ? skillState.get(key)! : (template?.skills.includes(key) ?? false),
  }));

  return {
    id: row.id,
    key: row.key,
    name: row.name,
    baseTemplate: row.baseTemplate,
    model: { gateway: storedModel.gateway ?? "", frontier: storedModel.frontier ?? "", preferFrontier: storedModel.preferFrontier ?? template?.preferFrontier ?? false },
    tools: row.tools,
    maxSteps: row.maxSteps,
    temperature: row.temperature,
    enabled: row.enabled,
    isTemplate: row.isTemplate,
    missionDefault: template?.mission ?? "",
    layers,
    skills,
    allTools: ALL_TOOL_NAMES,
    guardrails: GUARDRAILS,
  };
}

export interface UpdatePersonaPatch {
  name?: string;
  model?: { gateway: string; frontier?: string; preferFrontier?: boolean };
  tools?: ToolName[];
  maxSteps?: number;
  temperature?: number; // 0..1
  enabled?: boolean;
}

export async function updatePersona(workspaceId: string, personaId: string, patch: UpdatePersonaPatch, by: string): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.name !== undefined) set.name = patch.name.trim();
  if (patch.model !== undefined) set.modelJson = { gateway: patch.model.gateway, frontier: patch.model.frontier, preferFrontier: patch.model.preferFrontier ?? false };
  if (patch.tools !== undefined) set.toolsJson = patch.tools.filter((t) => ALL_TOOL_NAMES.includes(t));
  if (patch.maxSteps !== undefined) set.maxSteps = Math.max(1, Math.min(50, Math.round(patch.maxSteps)));
  if (patch.temperature !== undefined) set.temperature = Math.max(0, Math.min(100, Math.round(patch.temperature * 100)));
  if (patch.enabled !== undefined) set.enabled = patch.enabled;
  if (Object.keys(set).length === 0) return;
  await db().update(agentPersonas).set(set).where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId)));
  await appendAudit({ workspaceId, actorSub: by, event: "persona_updated", target: personaId });
}

/** Set (or clear, when content is blank) one editable prompt layer (1–4). */
export async function setPromptLayer(workspaceId: string, personaId: string, layer: number, content: string, by: string): Promise<void> {
  if (layer < 1 || layer > 4) throw new Error("layer must be 1–4 (guardrails are not editable)");
  const trimmed = content.trim();
  if (trimmed === "") {
    await db().delete(agentPrompts).where(and(eq(agentPrompts.workspaceId, workspaceId), eq(agentPrompts.personaId, personaId), eq(agentPrompts.layer, layer)));
  } else {
    await db()
      .insert(agentPrompts)
      .values({ workspaceId, personaId, layer, contentEnc: encryptField(workspaceId, trimmed), updatedBySub: by })
      .onConflictDoUpdate({
        target: [agentPrompts.personaId, agentPrompts.layer],
        set: { contentEnc: encryptField(workspaceId, trimmed), updatedBySub: by, updatedAt: new Date() },
      });
  }
  await appendAudit({ workspaceId, actorSub: by, event: "persona_prompt_set", target: `${personaId}:${layer}` });
}

export async function setSkillEnabled(workspaceId: string, personaId: string, skillKey: string, enabled: boolean): Promise<void> {
  await db()
    .insert(agentSkills)
    .values({ workspaceId, personaId, skillKey, enabled })
    .onConflictDoUpdate({ target: [agentSkills.personaId, agentSkills.skillKey], set: { enabled } });
}

async function uniqueKey(workspaceId: string, base: string): Promise<string> {
  const rows = await db().select({ key: agentPersonas.key }).from(agentPersonas).where(eq(agentPersonas.workspaceId, workspaceId));
  const taken = new Set(rows.map((r) => r.key));
  if (!taken.has(base)) return base;
  for (let i = 2; i < 1000; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
  return `${base}-${Date.now()}`;
}

/** Clone a persona into a new (non-template) persona, copying overrides + skills. */
export async function clonePersona(workspaceId: string, sourceId: string, name: string, by: string): Promise<string | null> {
  const cfg = await getPersonaConfig(workspaceId, sourceId);
  if (!cfg) return null;
  const key = await uniqueKey(workspaceId, slugify(name));
  const [row] = await db()
    .insert(agentPersonas)
    .values({
      workspaceId,
      key,
      name: name.trim() || `${cfg.name} (copy)`,
      baseTemplate: cfg.baseTemplate,
      modelJson: { gateway: cfg.model.gateway, frontier: cfg.model.frontier, preferFrontier: cfg.model.preferFrontier },
      toolsJson: cfg.tools,
      maxSteps: cfg.maxSteps,
      temperature: Math.round(cfg.temperature * 100),
      isTemplate: false,
      createdBy: by,
    })
    .returning({ id: agentPersonas.id });
  const newId = row!.id;
  for (const l of cfg.layers) await setPromptLayer(workspaceId, newId, l.layer, l.content, by);
  for (const s of cfg.skills) await setSkillEnabled(workspaceId, newId, s.key, s.enabled);
  await appendAudit({ workspaceId, actorSub: by, event: "persona_cloned", target: `${sourceId}->${newId}` });
  return newId;
}

/** Delete a non-template persona (templates are protected). */
export async function deletePersona(workspaceId: string, personaId: string, by: string): Promise<{ ok: boolean; error?: string }> {
  const [r] = await db().select({ isTemplate: agentPersonas.isTemplate }).from(agentPersonas).where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId))).limit(1);
  if (!r) return { ok: false, error: "not_found" };
  if (r.isTemplate) return { ok: false, error: "template_protected" };
  await db().delete(agentPrompts).where(and(eq(agentPrompts.workspaceId, workspaceId), eq(agentPrompts.personaId, personaId)));
  await db().delete(agentSkills).where(and(eq(agentSkills.workspaceId, workspaceId), eq(agentSkills.personaId, personaId)));
  await db().delete(agentPersonas).where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId)));
  await appendAudit({ workspaceId, actorSub: by, event: "persona_deleted", target: personaId });
  return { ok: true };
}

export interface PersonaExport {
  name: string;
  baseTemplate: string;
  model: { gateway: string; frontier: string; preferFrontier: boolean };
  tools: ToolName[];
  maxSteps: number;
  temperature: number;
  layers: { layer: number; content: string }[];
  skills: { key: SkillKey; enabled: boolean }[];
}

export async function exportPersona(workspaceId: string, personaId: string): Promise<PersonaExport | null> {
  const cfg = await getPersonaConfig(workspaceId, personaId);
  if (!cfg) return null;
  return {
    name: cfg.name,
    baseTemplate: cfg.baseTemplate,
    model: cfg.model,
    tools: cfg.tools,
    maxSteps: cfg.maxSteps,
    temperature: cfg.temperature,
    layers: cfg.layers,
    skills: cfg.skills.map((s) => ({ key: s.key, enabled: s.enabled })),
  };
}

export interface PersonaImport {
  name: string;
  baseTemplate?: string;
  model?: { gateway: string; frontier?: string; preferFrontier?: boolean };
  tools?: string[];
  maxSteps?: number;
  temperature?: number;
  layers?: { layer: number; content: string }[];
  skills?: { key: string; enabled: boolean }[];
}

/** Import a persona from an exported JSON shape as a new (non-template) persona. */
export async function importPersona(workspaceId: string, data: PersonaImport, by: string): Promise<string> {
  const key = await uniqueKey(workspaceId, slugify(data.name));
  const tools = (data.tools ?? []).filter((t): t is ToolName => (ALL_TOOL_NAMES as string[]).includes(t));
  const [row] = await db()
    .insert(agentPersonas)
    .values({
      workspaceId,
      key,
      name: (data.name || "Imported persona").slice(0, 80),
      baseTemplate: data.baseTemplate || "executive-assistant",
      modelJson: { gateway: data.model?.gateway ?? "", frontier: data.model?.frontier ?? "", preferFrontier: data.model?.preferFrontier ?? false },
      toolsJson: tools,
      maxSteps: Math.max(1, Math.min(50, data.maxSteps ?? 18)),
      temperature: Math.max(0, Math.min(100, Math.round((data.temperature ?? 0.3) * 100))),
      isTemplate: false,
      createdBy: by,
    })
    .returning({ id: agentPersonas.id });
  const newId = row!.id;
  for (const l of data.layers ?? []) if (l.layer >= 1 && l.layer <= 4 && l.content) await setPromptLayer(workspaceId, newId, l.layer, l.content, by);
  for (const s of data.skills ?? []) await setSkillEnabled(workspaceId, newId, s.key, s.enabled);
  await appendAudit({ workspaceId, actorSub: by, event: "persona_imported", target: newId });
  return newId;
}
