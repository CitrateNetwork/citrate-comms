/**
 * Saved CRM table views (COMMS-CRM-DEPTH D4). A view = chosen columns + sort + search,
 * per entity. Owned by a user; optionally shared with the workspace. Config is non-PII
 * (column keys, sort dir, the user's own search term).
 */
import { and, asc, eq, or } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmViews } from "@/lib/db/schema";
import type { CrmEntity } from "./crm-enums";

export interface ViewConfig {
  columns: string[];
  sort?: { key: string; dir: "asc" | "desc" };
  search?: string;
}
export interface SavedView {
  id: string;
  name: string;
  ownerSub: string;
  shared: boolean;
  config: ViewConfig;
  mine: boolean;
}

/** Views visible to a user: their own + shared ones, for this entity. */
export async function listViews(workspaceId: string, entity: CrmEntity, sub: string): Promise<SavedView[]> {
  const rows = await db()
    .select()
    .from(crmViews)
    .where(and(eq(crmViews.workspaceId, workspaceId), eq(crmViews.entity, entity), or(eq(crmViews.ownerSub, sub), eq(crmViews.shared, true))))
    .orderBy(asc(crmViews.name));
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    ownerSub: r.ownerSub,
    shared: r.shared,
    config: r.configJson as ViewConfig,
    mine: r.ownerSub === sub,
  }));
}

export async function saveView(args: {
  workspaceId: string;
  entity: CrmEntity;
  name: string;
  ownerSub: string;
  shared?: boolean;
  config: ViewConfig;
}): Promise<SavedView> {
  const [row] = await db()
    .insert(crmViews)
    .values({
      workspaceId: args.workspaceId,
      entity: args.entity,
      name: args.name.trim().slice(0, 80),
      ownerSub: args.ownerSub,
      shared: args.shared ?? false,
      configJson: args.config,
    })
    .returning();
  return { id: row!.id, name: row!.name, ownerSub: row!.ownerSub, shared: row!.shared, config: row!.configJson as ViewConfig, mine: true };
}

/** Delete a view the caller owns. */
export async function deleteView(workspaceId: string, viewId: string, sub: string): Promise<void> {
  await db()
    .delete(crmViews)
    .where(and(eq(crmViews.workspaceId, workspaceId), eq(crmViews.id, viewId), eq(crmViews.ownerSub, sub)));
}
