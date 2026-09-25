import { NextResponse } from "next/server";
import { requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { readRows } from "@/lib/domain/tables-repo";

export const runtime = "nodejs";

/** A bounded window of a sheet's rows (sensitive values masked). Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; sheetId: string }> }) {
  try {
    const { id, sheetId } = await params;
    await requireInternal(req, id);
    const url = new URL(req.url);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    const columnsParam = url.searchParams.get("columns");
    const columns = columnsParam ? columnsParam.split(",").map((s) => s.trim()).filter(Boolean) : undefined;
    return NextResponse.json(await readRows(id, sheetId, { offset, limit, columns }));
  } catch (e) {
    return errorResponse(e);
  }
}
