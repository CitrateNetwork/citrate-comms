import { NextResponse } from "next/server";
import { requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { verifyChainFromDb } from "@/lib/audit/chain";

export const runtime = "nodejs";

/** Re-walk the workspace's BLAKE3 audit chain and recompute every hash. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireInternal(req, id);
    return NextResponse.json({ integrity: await verifyChainFromDb(id) });
  } catch (e) {
    return errorResponse(e);
  }
}
