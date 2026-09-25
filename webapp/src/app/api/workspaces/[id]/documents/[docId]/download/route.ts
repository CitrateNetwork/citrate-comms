import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { appendAudit } from "@/lib/audit/chain";
import { getDocument, getVisibleDocument } from "@/lib/domain/documents";
import { isInternalRole } from "@/lib/rbac/matrix";

export const runtime = "nodejs";

/**
 * Audited, access-controlled download proxy (ATT-DL). Authorization is per document
 * (PBA-L3c-003): a file uploaded into (or shared into) a channel/DM is downloadable only by
 * that channel's members; a workspace-level file only by internal roles. A workspace
 * member who can't see the file gets 403; a non-member is rejected. Every download appends a
 * `document_downloaded` audit row, then we redirect to the Blob with download disposition.
 * This is the URL surfaced in the UI's download buttons; inline image/video display uses
 * `?inline=1` (same authorization, no audit row per impression) — clients never receive
 * the raw Blob URL (PBA-L3c-009).
 */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; docId: string }> }) {
  try {
    const { id, docId } = await params;
    const ctx = await requireMember(req, id); // membership gate (fail-closed)
    const doc = await getVisibleDocument(id, docId, { sub: ctx.sub, internal: isInternalRole(ctx.role) });
    if (!doc) {
      const exists = await getDocument(id, docId);
      return exists
        ? NextResponse.json({ error: "forbidden" }, { status: 403 })
        : NextResponse.json({ error: "not_found" }, { status: 404 });
    }
    if (!doc.blobUrl) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Inline display (image/video in a message) is authorized exactly like a download
    // but not written to the audit chain on every impression (PBA-L3c-009).
    if (new URL(req.url).searchParams.get("inline") === "1") {
      return NextResponse.redirect(doc.blobUrl, { status: 302, headers: { "cache-control": "private, no-store" } });
    }

    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "document_downloaded", target: docId });

    const dl = `${doc.blobUrl}${doc.blobUrl.includes("?") ? "&" : "?"}download=1`;
    return NextResponse.redirect(dl, { status: 302, headers: { "cache-control": "private, no-store" } });
  } catch (e) {
    return errorResponse(e);
  }
}
