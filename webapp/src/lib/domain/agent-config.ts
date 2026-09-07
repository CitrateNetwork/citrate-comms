/**
 * CFG — per-persona resources/knowledge-bases + config-rights delegation.
 *
 * Resources: knowledge an owner pins to a persona (inline text, reference links, or pinned
 * documents). Enabled items are folded into the persona's system prompt at runtime so the
 * agent answers from the org's own material. Text is encrypted at rest.
 *
 * Delegation: an Owner/Admin can grant a specific member the right to CONFIGURE a persona
 * (its resources, prompts, skills, settings) without making them a full workspace admin.
 * `canConfigurePersona` is the single authority both the editor pages and the API routes
 * consult — admins always pass; granted members pass for the persona(s) they hold.
 */
import { and, eq, isNull, or } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agentResources, agentConfigGrants, members } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { can, Capability, type Role } from "@/lib/rbac/matrix";

// ── Resources ────────────────────────────────────────────────────────────────

export type ResourceKind = "text" | "link" | "document";

export interface ResourceRow {
  id: string;
  personaId: string;
  kind: ResourceKind;
  title: string;
  content: string | null; // decrypted text (kind=text)
  url: string | null;
  documentId: string | null;
  enabled: boolean;
}

export async function listResources(workspaceId: string, personaId: string): Promise<ResourceRow[]> {
  const rows = await db()
    .select()
    .from(agentResources)
    .where(and(eq(agentResources.workspaceId, workspaceId), eq(agentResources.personaId, personaId)));
  return rows.map((r) => ({
    id: r.id,
    personaId: r.personaId,
    kind: r.kind as ResourceKind,
    title: r.title,
    content: r.contentEnc ? safeDecrypt(workspaceId, r.contentEnc) : null,
    url: r.url,
    documentId: r.documentId,
    enabled: r.enabled,
  }));
}

export async function addResource(
  workspaceId: string,
  personaId: string,
  input: { kind: ResourceKind; title: string; content?: string; url?: string; documentId?: string },
  by: string,
): Promise<string | null> {
  const title = input.title.trim().slice(0, 200) || "Untitled";
  const values: typeof agentResources.$inferInsert = {
    workspaceId,
    personaId,
    kind: input.kind,
    title,
    createdBySub: by,
    contentEnc: null,
    url: null,
    documentId: null,
  };
  if (input.kind === "text") {
    const c = (input.content ?? "").trim();
    if (!c) return null;
    values.contentEnc = encryptField(workspaceId, c.slice(0, 20_000));
  } else if (input.kind === "link") {
    const u = (input.url ?? "").trim();
    if (!/^https?:\/\//i.test(u)) return null;
    values.url = u.slice(0, 2000);
  } else if (input.kind === "document") {
    if (!input.documentId) return null;
    values.documentId = input.documentId;
  } else {
    return null;
  }
  const [row] = await db().insert(agentResources).values(values).returning({ id: agentResources.id });
  await appendAudit({ workspaceId, actorSub: by, event: "persona_resource_added", target: `${personaId}:${input.kind}` });
  return row?.id ?? null;
}

export async function setResourceEnabled(
  workspaceId: string,
  personaId: string,
  resourceId: string,
  enabled: boolean,
  by: string,
): Promise<void> {
  // Scope the mutation to the persona the caller was authorized for. Without the
  // personaId predicate a delegate scoped to persona A could toggle persona B's
  // resources (which are injected into B's system prompt) — CM2-B-B013.
  await db()
    .update(agentResources)
    .set({ enabled })
    .where(
      and(
        eq(agentResources.workspaceId, workspaceId),
        eq(agentResources.personaId, personaId),
        eq(agentResources.id, resourceId),
      ),
    );
  await appendAudit({ workspaceId, actorSub: by, event: "persona_resource_toggled", target: `${personaId}:${resourceId}` });
}

export async function deleteResource(
  workspaceId: string,
  personaId: string,
  resourceId: string,
  by: string,
): Promise<void> {
  await db()
    .delete(agentResources)
    .where(
      and(
        eq(agentResources.workspaceId, workspaceId),
        eq(agentResources.personaId, personaId),
        eq(agentResources.id, resourceId),
      ),
    );
  await appendAudit({ workspaceId, actorSub: by, event: "persona_resource_deleted", target: `${personaId}:${resourceId}` });
}

/** Runtime: enabled resources rendered for the system prompt (CFG injection). */
export interface PersonaResourceForPrompt {
  kind: ResourceKind;
  title: string;
  content?: string;
  url?: string;
}
export async function resolvePersonaResources(workspaceId: string, personaId: string): Promise<PersonaResourceForPrompt[]> {
  const rows = await listResources(workspaceId, personaId);
  return rows
    .filter((r) => r.enabled)
    .map((r) => ({
      kind: r.kind,
      title: r.title,
      content: r.kind === "text" ? r.content ?? undefined : undefined,
      url: r.kind === "link" ? r.url ?? undefined : undefined,
    }));
}

// ── Delegation ───────────────────────────────────────────────────────────────

export interface ConfigGrantRow {
  id: string;
  granteeSub: string;
  granteeName: string | null;
  personaId: string | null; // null = all personas
  grantedBySub: string;
  createdAt: string;
}

export async function listConfigGrants(workspaceId: string): Promise<ConfigGrantRow[]> {
  const rows = await db()
    .select({
      id: agentConfigGrants.id,
      granteeSub: agentConfigGrants.granteeSub,
      granteeName: members.displayName,
      personaId: agentConfigGrants.personaId,
      grantedBySub: agentConfigGrants.grantedBySub,
      createdAt: agentConfigGrants.createdAt,
    })
    .from(agentConfigGrants)
    .leftJoin(members, and(eq(members.workspaceId, agentConfigGrants.workspaceId), eq(members.sub, agentConfigGrants.granteeSub)))
    .where(eq(agentConfigGrants.workspaceId, workspaceId));
  return rows.map((r) => ({
    id: r.id,
    granteeSub: r.granteeSub,
    granteeName: r.granteeName ?? null,
    personaId: r.personaId,
    grantedBySub: r.grantedBySub,
    createdAt: r.createdAt.toISOString(),
  }));
}

/** Grant config rights (idempotent on (grantee, personaId)). personaId null = all personas. */
export async function grantConfig(workspaceId: string, granteeSub: string, personaId: string | null, by: string): Promise<void> {
  const dupe = await db()
    .select({ id: agentConfigGrants.id })
    .from(agentConfigGrants)
    .where(
      and(
        eq(agentConfigGrants.workspaceId, workspaceId),
        eq(agentConfigGrants.granteeSub, granteeSub),
        personaId === null ? isNull(agentConfigGrants.personaId) : eq(agentConfigGrants.personaId, personaId),
      ),
    )
    .limit(1);
  if (dupe.length > 0) return;
  await db().insert(agentConfigGrants).values({ workspaceId, granteeSub, personaId, grantedBySub: by });
  await appendAudit({ workspaceId, actorSub: by, event: "persona_config_granted", target: `${granteeSub}:${personaId ?? "all"}` });
}

export async function revokeConfig(workspaceId: string, grantId: string, by: string): Promise<void> {
  await db().delete(agentConfigGrants).where(and(eq(agentConfigGrants.workspaceId, workspaceId), eq(agentConfigGrants.id, grantId)));
  await appendAudit({ workspaceId, actorSub: by, event: "persona_config_revoked", target: grantId });
}

/**
 * The single config-rights authority. Admins (ManageWorkspace) always pass. Otherwise the
 * member must hold a grant covering this persona — either a workspace-wide grant
 * (personaId null) or one specifically for this persona.
 */
export async function canConfigurePersona(workspaceId: string, sub: string, role: Role, personaId: string): Promise<boolean> {
  if (can(role, Capability.ManageWorkspace)) return true;
  const [g] = await db()
    .select({ id: agentConfigGrants.id })
    .from(agentConfigGrants)
    .where(
      and(
        eq(agentConfigGrants.workspaceId, workspaceId),
        eq(agentConfigGrants.granteeSub, sub),
        or(isNull(agentConfigGrants.personaId), eq(agentConfigGrants.personaId, personaId)),
      ),
    )
    .limit(1);
  return Boolean(g);
}

/** Does this member have ANY config grant (used to surface the editor entry point)? */
export async function hasAnyConfigGrant(workspaceId: string, sub: string): Promise<boolean> {
  const [g] = await db()
    .select({ id: agentConfigGrants.id })
    .from(agentConfigGrants)
    .where(and(eq(agentConfigGrants.workspaceId, workspaceId), eq(agentConfigGrants.granteeSub, sub)))
    .limit(1);
  return Boolean(g);
}

/** Persona ids a non-admin member may configure (admins pass null = all). */
export async function configurablePersonaIds(workspaceId: string, sub: string): Promise<{ all: boolean; ids: string[] }> {
  const rows = await db()
    .select({ personaId: agentConfigGrants.personaId })
    .from(agentConfigGrants)
    .where(and(eq(agentConfigGrants.workspaceId, workspaceId), eq(agentConfigGrants.granteeSub, sub)));
  if (rows.some((r) => r.personaId === null)) return { all: true, ids: [] };
  return { all: false, ids: rows.map((r) => r.personaId!).filter(Boolean) };
}

function safeDecrypt(workspaceId: string, packed: string): string {
  try {
    return decryptField(workspaceId, packed);
  } catch {
    return "⚠︎ couldn't decrypt";
  }
}
