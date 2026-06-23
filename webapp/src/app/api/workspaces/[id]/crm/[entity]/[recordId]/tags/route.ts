import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmTagAddSchema, crmTagRemoveSchema } from "@/lib/validation/schemas";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { recordExists } from "@/lib/domain/crm";
import { createTag, tagRecord, untagRecord } from "@/lib/domain/crm-tags";

export const runtime = "nodejs";

function parseEntity(s: string): CrmEntity | null {
  return (CRM_ENTITIES as readonly string[]).includes(s) ? (s as CrmEntity) : null;
}

/** Tag a record (by existing tagId or a new label). Member+ via CreateRecord. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; entity: string; recordId: string }> }) {
  try {
    const { id, entity: entityRaw, recordId } = await params;
    const entity = parseEntity(entityRaw);
    if (!entity) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    if (!(await recordExists(id, entity, recordId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const parsed = crmTagAddSchema.safeParse(await readJson(req));
    if (!parsed.success || (!parsed.data.tagId && !parsed.data.label)) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const tagId = parsed.data.tagId ?? (await createTag(id, parsed.data.label!)).id;
    await tagRecord({ workspaceId: id, entity, recordId, tagId, actorSub: ctx.sub });
    return NextResponse.json({ ok: true, tagId }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Remove a tag from a record. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; entity: string; recordId: string }> }) {
  try {
    const { id, entity: entityRaw, recordId } = await params;
    const entity = parseEntity(entityRaw);
    if (!entity) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    await requireCapability(req, id, Capability.CreateRecord);
    const parsed = crmTagRemoveSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await untagRecord(id, entity, recordId, parsed.data.tagId);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
