import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { listTables } from "@/lib/domain/tables-repo";

export const runtime = "nodejs";

/** Dropped data tables (sheets) + recent import jobs. Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireMember(req, id);
    const url = new URL(req.url);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    return NextResponse.json(await listTables(id, limit));
  } catch (e) {
    return errorResponse(e);
  }
}
