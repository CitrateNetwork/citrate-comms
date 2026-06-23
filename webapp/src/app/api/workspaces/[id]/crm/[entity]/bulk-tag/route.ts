import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmBulkTagSchema } from "@/lib/validation/schemas";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { createTag, bulkTagRecords } from "@/lib/domain/crm-tags";

export const runtime = "nodejs";

/** Apply one tag to many records (D4 bulk action). Member+ via CreateRecord. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; entity: string }> }) {
  try {
    const { id, entity: entityRaw } = await params;
    if (!(CRM_ENTITIES as readonly string[]).includes(entityRaw)) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = crmBulkTagSchema.safeParse(await readJson(req));
    if (!parsed.success || (!parsed.data.tagId && !parsed.data.label)) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const tagId = parsed.data.tagId ?? (await createTag(id, parsed.data.label!)).id;
    const n = await bulkTagRecords({ workspaceId: id, entity: entityRaw as CrmEntity, recordIds: parsed.data.recordIds, tagId, actorSub: ctx.sub });
    return NextResponse.json({ ok: true, tagged: n, tagId });
  } catch (e) {
    return errorResponse(e);
  }
}
