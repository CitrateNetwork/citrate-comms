import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmRecordUpdateSchema } from "@/lib/validation/schemas";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { recordExists, updateAccount, updateDeal, updateContact } from "@/lib/domain/crm";

export const runtime = "nodejs";

function parseEntity(s: string): CrmEntity | null {
  return (CRM_ENTITIES as readonly string[]).includes(s) ? (s as CrmEntity) : null;
}

/** Update a record's standard fields (Member+ via CreateRecord). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; entity: string; recordId: string }> }) {
  try {
    const { id, entity: entityRaw, recordId } = await params;
    const entity = parseEntity(entityRaw);
    if (!entity) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    if (!(await recordExists(id, entity, recordId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const parsed = crmRecordUpdateSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const p = parsed.data;
    if (entity === "account") await updateAccount(id, recordId, { name: p.name, domain: p.domain }, ctx.sub);
    else if (entity === "deal") await updateDeal(id, recordId, { name: p.name, valueMinor: p.valueMinor }, ctx.sub);
    else await updateContact(id, recordId, { name: p.name, title: p.title }, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
