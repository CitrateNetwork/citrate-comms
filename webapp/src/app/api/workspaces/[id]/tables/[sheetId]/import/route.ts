import { NextResponse } from "next/server";
import { requireCapability, Capability, requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { getMapping, previewImport, approveMapping, createImportJob, runImportSlice } from "@/lib/domain/import-engine";

export const runtime = "nodejs";
export const maxDuration = 120;

/** Dry-run preview for the sheet's saved mapping (N new / M updated / K held). Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; sheetId: string }> }) {
  try {
    const { id, sheetId } = await params;
    await requireInternal(req, id);
    const mapping = await getMapping(id, sheetId);
    if (!mapping) return NextResponse.json({ error: "no_mapping" }, { status: 400 });
    return NextResponse.json({ preview: await previewImport(id, sheetId, mapping.spec) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Human-initiated import: approves the mapping, starts the job, runs the first slice.
 *  Remaining slices continue via the job tick. Member+ (CreateRecord). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; sheetId: string }> }) {
  try {
    const { id, sheetId } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const mapping = await getMapping(id, sheetId);
    if (!mapping) return NextResponse.json({ error: "no_mapping" }, { status: 400 });
    await approveMapping(id, mapping.id);
    const jobId = await createImportJob({ workspaceId: id, sheetId, mappingId: mapping.id, bySub: ctx.sub });
    const progress = await runImportSlice(id, jobId);
    return NextResponse.json({ jobId, progress }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
