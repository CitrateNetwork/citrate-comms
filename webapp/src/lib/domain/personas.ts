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
import { decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import {
  DEFAULT_PERSONA_LIST,
  DEFAULT_PERSONAS,
  type PersonaKey,
  type PersonaModel,
  type SkillKey,
  type ToolName,
} from "@/lib/ai/personas";

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
  // Top up the default personas' tool allow-lists to the current templates, so
  // workspaces seeded before new tools shipped (e.g. crm.note/crm.write) gain them.
  // Safe today: there is no persona tool-customization UI to clobber.
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

  return {
    ...row,
    mission: byLayer.get(1) || template?.mission || `You are ${row.name}.`,
    preferFrontier: storedModel.preferFrontier ?? template?.preferFrontier ?? false,
    skills,
    overrides: {
      mission: byLayer.get(1),
      capabilities: byLayer.get(2),
      workspaceKnowledge: byLayer.get(3),
      skills: byLayer.get(4),
    },
  };
}
