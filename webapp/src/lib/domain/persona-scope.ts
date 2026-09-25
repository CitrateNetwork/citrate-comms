/**
 * Persona tenant binding (PBA-L3c-001). A persona id is only meaningful inside the
 * workspace that owns it. Every persona-config write (prompts, skills, resources,
 * delegation grants) and the config-rights check itself first confirm
 * `agent_personas.workspace_id = ws AND id = personaId`; the upserts additionally carry a
 * workspace `setWhere` so a conflicting row owned by another tenant is never rewritten,
 * and migration 0016 adds composite (workspace_id, persona_id) foreign keys.
 */
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agentPersonas } from "@/lib/db/schema";
import { GuardError } from "@/lib/tenant/guard";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** True iff `personaId` is a persona of `workspaceId`. */
export async function personaInWorkspace(workspaceId: string, personaId: string): Promise<boolean> {
  if (!UUID_RE.test(personaId)) return false; // never let a malformed id reach a uuid column
  const [r] = await db()
    .select({ id: agentPersonas.id })
    .from(agentPersonas)
    .where(and(eq(agentPersonas.workspaceId, workspaceId), eq(agentPersonas.id, personaId)))
    .limit(1);
  return Boolean(r);
}

/** Throw a 403 GuardError unless `personaId` belongs to `workspaceId`. */
export async function assertPersonaInWorkspace(workspaceId: string, personaId: string): Promise<void> {
  if (!(await personaInWorkspace(workspaceId, personaId))) throw new GuardError(403, "persona not in this workspace");
}
