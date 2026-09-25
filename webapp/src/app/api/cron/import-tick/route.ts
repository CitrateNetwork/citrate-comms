import { NextResponse } from "next/server";
import { bearerMatches } from "@/lib/security/bearer";
import { errorResponse } from "@/lib/http";
import { listActiveJobs, runImportSlice } from "@/lib/domain/import-engine";

export const runtime = "nodejs";
export const maxDuration = 300;

/**
 * Unattended import-job continuation. Vercel Cron hits this on a schedule; it advances
 * every queued/running job by one slice so large imports finish without a human keeping
 * a tab open. Authorized by the platform Cron header (CRON_SECRET). If no secret is set,
 * the route refuses — fail-closed.
 */
export async function GET(req: Request) {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return NextResponse.json({ error: "cron_disabled" }, { status: 503 });
    const auth = req.headers.get("authorization");
    if (!bearerMatches(auth, secret)) return NextResponse.json({ error: "unauthorized" }, { status: 401 }); // PBA-L3c-035

    const jobs = await listActiveJobs(25);
    const results: { id: string; status: string; cursor: number; total: number }[] = [];
    for (const j of jobs) {
      try {
        const p = await runImportSlice(j.workspaceId, j.id);
        results.push({ id: p.id, status: p.status, cursor: p.cursor, total: p.total });
      } catch {
        results.push({ id: j.id, status: "error", cursor: 0, total: 0 });
      }
    }
    return NextResponse.json({ ticked: results.length, jobs: results });
  } catch (e) {
    return errorResponse(e);
  }
}
