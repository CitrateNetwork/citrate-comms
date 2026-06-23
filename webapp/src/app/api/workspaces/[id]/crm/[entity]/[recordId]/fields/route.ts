import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmFieldValueSchema } from "@/lib/validation/schemas";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { recordExists } from "@/lib/domain/crm";
import { setFieldValue } from "@/lib/domain/crm-fields";

export const runtime = "nodejs";

function parseEntity(s: string): CrmEntity | null {
  return (CRM_ENTITIES as readonly string[]).includes(s) ? (s as CrmEntity) : null;
}

/** Set a custom field value on a record (Member+ via CreateRecord). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; entity: string; recordId: string }> }) {
  try {
    const { id, entity: entityRaw, recordId } = await params;
    const entity = parseEntity(entityRaw);
    if (!entity) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    if (!(await recordExists(id, entity, recordId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const parsed = crmFieldValueSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setFieldValue({ workspaceId: id, entity, recordId, fieldId: parsed.data.fieldId, raw: parsed.data.value, bySub: ctx.sub });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
