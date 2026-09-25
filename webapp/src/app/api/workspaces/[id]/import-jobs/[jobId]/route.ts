import { NextResponse } from "next/server";
import { requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { getJob } from "@/lib/domain/import-engine";

export const runtime = "nodejs";

/** Import-job progress (for the progress UI to poll). Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; jobId: string }> }) {
  try {
    const { id, jobId } = await params;
    await requireInternal(req, id);
    const job = await getJob(id, jobId);
    if (!job) return NextResponse.json({ error: "not_found" }, { status: 404 });
    return NextResponse.json(job);
  } catch (e) {
    return errorResponse(e);
  }
}
