import { NextResponse } from "next/server";
import { requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { getSheetSchema } from "@/lib/domain/tables-repo";

export const runtime = "nodejs";

/** A sheet's column profile (types, sensitivity, samples). Any member. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; sheetId: string }> }) {
  try {
    const { id, sheetId } = await params;
    await requireInternal(req, id);
    const schema = await getSheetSchema(id, sheetId);
    if (!schema) return NextResponse.json({ error: "not_found" }, { status: 404 });
    return NextResponse.json(schema);
  } catch (e) {
    return errorResponse(e);
  }
}
