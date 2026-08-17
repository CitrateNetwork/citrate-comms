import { NextResponse } from "next/server";
import { requireCapability, Capability } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { runImportSlice } from "@/lib/domain/import-engine";

export const runtime = "nodejs";
export const maxDuration = 120;

/** Advance a resumable import job by one slice. Driven by the progress UI (polling)
 *  and the cron. Idempotent-ish — dedupe absorbs any re-processing. Member+ (CreateRecord). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; jobId: string }> }) {
  try {
    const { id, jobId } = await params;
    await requireCapability(req, id, Capability.CreateRecord);
    const progress = await runImportSlice(id, jobId);
    return NextResponse.json(progress);
  } catch (e) {
    return errorResponse(e);
  }
}
