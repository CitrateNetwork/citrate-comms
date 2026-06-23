import { NextResponse } from "next/server";
import { Capability, requireCapability, requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmViewSaveSchema, crmViewDeleteSchema } from "@/lib/validation/schemas";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { listViews, saveView, deleteView } from "@/lib/domain/crm-views";

export const runtime = "nodejs";

/** Saved views for an entity (own + shared). Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const url = new URL(req.url);
    const entity = url.searchParams.get("entity");
    if (!entity || !(CRM_ENTITIES as readonly string[]).includes(entity)) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    return NextResponse.json({ views: await listViews(id, entity as CrmEntity, ctx.sub) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Save a view (Member+ via CreateRecord). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = crmViewSaveSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const view = await saveView({ workspaceId: id, ownerSub: ctx.sub, ...parsed.data });
    return NextResponse.json({ view }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Delete one of your own views. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const parsed = crmViewDeleteSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await deleteView(id, parsed.data.viewId, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
