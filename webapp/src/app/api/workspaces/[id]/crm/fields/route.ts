import { NextResponse } from "next/server";
import { Capability, requireCapability, requireInternal } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmFieldDefCreateSchema } from "@/lib/validation/schemas";
import { listFieldDefs, createFieldDef } from "@/lib/domain/crm-fields";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";

export const runtime = "nodejs";

/** List custom field definitions (optionally per entity; ?all=1 includes disabled). */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireInternal(req, id);
    const url = new URL(req.url);
    const includeDisabled = url.searchParams.get("all") === "1";
    const entityParam = url.searchParams.get("entity") as CrmEntity | null;
    const entities = entityParam && CRM_ENTITIES.includes(entityParam) ? [entityParam] : CRM_ENTITIES;
    const out: Record<string, unknown> = {};
    for (const e of entities) out[e] = await listFieldDefs(id, e, { includeDisabled });
    return NextResponse.json({ fields: out });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Define a new custom field (Owner/Admin). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const parsed = crmFieldDefCreateSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });
    const def = await createFieldDef({ workspaceId: id, createdBy: ctx.sub, ...parsed.data });
    return NextResponse.json({ field: def }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
