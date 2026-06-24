import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { appendAudit } from "@/lib/audit/chain";
import { getDocument } from "@/lib/domain/documents";

export const runtime = "nodejs";

/**
 * Audited, access-controlled download proxy (ATT-DL). Any active workspace member (members +
 * admins) may download; a non-member is rejected. Every download appends a
 * `document_downloaded` audit row, then we redirect to the Blob with download disposition.
 * This is the URL surfaced in the UI's download buttons; inline image/video display uses the
 * raw Blob URL so it isn't audited on every impression.
 */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; docId: string }> }) {
  try {
    const { id, docId } = await params;
    const ctx = await requireMember(req, id); // membership gate (fail-closed)
    const doc = await getDocument(id, docId);
    if (!doc || !doc.blobUrl) return NextResponse.json({ error: "not_found" }, { status: 404 });

    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "document_downloaded", target: docId });

    const dl = `${doc.blobUrl}${doc.blobUrl.includes("?") ? "&" : "?"}download=1`;
    return NextResponse.redirect(dl, 302);
  } catch (e) {
    return errorResponse(e);
  }
}
