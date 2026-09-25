import { NextResponse } from "next/server";
import { requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { queryRecords } from "@/lib/domain/crm-query";

export const runtime = "nodejs";

/** The flat, sortable table for an entity (standard + custom columns). Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; entity: string }> }) {
  try {
    const { id, entity: entityRaw } = await params;
    if (!(CRM_ENTITIES as readonly string[]).includes(entityRaw)) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    await requireInternal(req, id);
    return NextResponse.json(await queryRecords(id, entityRaw as CrmEntity));
  } catch (e) {
    return errorResponse(e);
  }
}
