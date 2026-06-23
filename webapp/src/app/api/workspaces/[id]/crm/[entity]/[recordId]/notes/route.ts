import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { crmNoteSchema, crmNotePinSchema } from "@/lib/validation/schemas";
import { CRM_ENTITIES, type CrmEntity } from "@/lib/domain/crm-enums";
import { recordExists } from "@/lib/domain/crm";
import { addNote, setNotePinned } from "@/lib/domain/crm-notes";

export const runtime = "nodejs";

function parseEntity(s: string): CrmEntity | null {
  return (CRM_ENTITIES as readonly string[]).includes(s) ? (s as CrmEntity) : null;
}

/** Add a note/journal entry to a record (Member+ via CreateRecord). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; entity: string; recordId: string }> }) {
  try {
    const { id, entity: entityRaw, recordId } = await params;
    const entity = parseEntity(entityRaw);
    if (!entity) return NextResponse.json({ error: "bad_entity" }, { status: 400 });
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    if (!(await recordExists(id, entity, recordId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const parsed = crmNoteSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const note = await addNote({ workspaceId: id, entity, recordId, authorSub: ctx.sub, ...parsed.data });
    return NextResponse.json({ note }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Pin / unpin a note. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string; entity: string; recordId: string }> }) {
  try {
    const { id } = await params;
    await requireCapability(req, id, Capability.CreateRecord);
    const parsed = crmNotePinSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setNotePinned(id, parsed.data.noteId, parsed.data.pinned);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
