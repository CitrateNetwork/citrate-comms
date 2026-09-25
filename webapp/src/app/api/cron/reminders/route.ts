import { NextResponse } from "next/server";
import { bearerMatches } from "@/lib/security/bearer";
import { errorResponse } from "@/lib/http";
import { runDueReminders } from "@/lib/domain/calendar";

export const runtime = "nodejs";
export const maxDuration = 300;

/**
 * Calendar reminder dispatcher. Vercel Cron hits this on a schedule; it delivers every
 * due, unsent reminder (in-app notification + email in the recipient's timezone) and
 * marks it sent. Authorized by the platform Cron header (CRON_SECRET); fail-closed.
 */
export async function GET(req: Request) {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return NextResponse.json({ error: "cron_disabled" }, { status: 503 });
    const auth = req.headers.get("authorization");
    if (!bearerMatches(auth, secret)) return NextResponse.json({ error: "unauthorized" }, { status: 401 }); // PBA-L3c-035
    const result = await runDueReminders(300);
    return NextResponse.json(result);
  } catch (e) {
    return errorResponse(e);
  }
}
