import { NextResponse } from "next/server";
import { requireMember, requireCapability, Capability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { getMapping, saveMapping } from "@/lib/domain/import-engine";
import { suggestMapping, type MappingSpec } from "@/lib/domain/import-map";
import { getSheetSchema } from "@/lib/domain/tables-repo";

export const runtime = "nodejs";

/** The saved mapping for a sheet, or a fresh suggestion if none exists. Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; sheetId: string }> }) {
  try {
    const { id, sheetId } = await params;
    await requireMember(req, id);
    const existing = await getMapping(id, sheetId);
    if (existing) return NextResponse.json({ spec: existing.spec, approved: existing.approved, source: "saved" });
    const schema = await getSheetSchema(id, sheetId);
    if (!schema) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const spec = suggestMapping(schema.columns.map((c) => ({ name: c.name, type: c.type as never, sensitive: c.sensitive, nullFrac: c.nullFrac, samples: c.samples })));
    return NextResponse.json({ spec, approved: false, source: "suggested" });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Save an edited draft mapping. Member+ (CreateRecord). */
export async function PUT(req: Request, { params }: { params: Promise<{ id: string; sheetId: string }> }) {
  try {
    const { id, sheetId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const body = (await readJson(req)) as { spec?: MappingSpec };
    if (!body?.spec) return NextResponse.json({ error: "spec required" }, { status: 400 });
    const mappingId = await saveMapping({ workspaceId: id, sheetId, spec: body.spec, bySub: ctx.sub });
    return NextResponse.json({ ok: true, mappingId });
  } catch (e) {
    return errorResponse(e);
  }
}
