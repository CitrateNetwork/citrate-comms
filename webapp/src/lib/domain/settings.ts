/**
 * Workspace settings repository. Workspace-level config (notifications defaults,
 * automation, appearance) lives in a single JSONB row admins manage; per-user
 * identity (display name) lives on the member row. All real, persisted — no mocks.
 */
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { members, workspaceSettings } from "@/lib/db/schema";

export interface WorkspaceSettings {
  notifications?: Record<string, "all" | "mentions" | "mute">;
  automation?: { autoWitness: boolean };
  appearance?: { density?: "cinematic" | "compact"; accent?: string; reducedMotion?: boolean };
}

const DEFAULTS: WorkspaceSettings = {
  notifications: {},
  automation: { autoWitness: false },
  appearance: { density: "cinematic", accent: "green", reducedMotion: false },
};

export async function getSettings(workspaceId: string): Promise<WorkspaceSettings> {
  const [row] = await db()
    .select({ settings: workspaceSettings.settings })
    .from(workspaceSettings)
    .where(eq(workspaceSettings.workspaceId, workspaceId))
    .limit(1);
  return { ...DEFAULTS, ...((row?.settings as WorkspaceSettings) ?? {}) };
}

/** Merge a partial settings patch into the workspace JSONB (upsert). */
export async function updateSettings(workspaceId: string, patch: Partial<WorkspaceSettings>): Promise<WorkspaceSettings> {
  const current = await getSettings(workspaceId);
  const next: WorkspaceSettings = {
    notifications: { ...current.notifications, ...patch.notifications },
    automation: { ...current.automation, ...patch.automation } as WorkspaceSettings["automation"],
    appearance: { ...current.appearance, ...patch.appearance },
  };
  await db()
    .insert(workspaceSettings)
    .values({ workspaceId, settings: next })
    .onConflictDoUpdate({ target: workspaceSettings.workspaceId, set: { settings: next } });
  return next;
}

/** Update the caller's display name within a workspace. */
export async function updateDisplayName(workspaceId: string, sub: string, displayName: string): Promise<void> {
  await db()
    .update(members)
    .set({ displayName: displayName.trim() })
    .where(and(eq(members.workspaceId, workspaceId), eq(members.sub, sub)));
}
