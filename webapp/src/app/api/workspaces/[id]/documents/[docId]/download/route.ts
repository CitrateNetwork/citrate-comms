import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { appendAudit } from "@/lib/audit/chain";
import { getDocument, getVisibleDocument } from "@/lib/domain/documents";
import { isInternalRole } from "@/lib/rbac/matrix";
import { signedReadUrl, streamLegacyBlobResponse } from "@/lib/security/blob-signing";

export const runtime = "nodejs";

/**
 * Audited, access-controlled download proxy (ATT-DL / ATT-HARDEN). Authorization is per
 * document (PBA-L3c-003): a file uploaded into (or shared into) a channel/DM is downloadable
 * only by that channel's members; a workspace-level file only by internal roles. A workspace
 * member who can't see the file gets 403; a non-member is rejected. Every download (not inline
 * impression) appends a `document_downloaded` audit row.
 *
 * Only AFTER that per-document authorization does the proxy mint a short-lived, object-scoped
 * signed URL for the private-store object and redirect to it — the client never receives the
 * underlying store URL, and a captured signed link stops working once its TTL lapses
 * (PBA-L3c-009). This is the URL surfaced in the UI's download buttons; inline image/video
 * display uses `?inline=1` (same authorization, no audit row per impression).
 *
 * Legacy objects that predate the private-store migration are STREAMED through the proxy
 * (their bytes, never their URL) during the transition; the migration
 * (scripts/harden-attachment-store.mjs) moves them into the private store, after which every
 * served attachment flows through the signed path and the public store is deleted.
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

    const inline = new URL(req.url).searchParams.get("inline") === "1";
    // Inline display is authorized exactly like a download but not written to the audit
    // chain on every impression (PBA-L3c-009).
    if (!inline) {
      await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "document_downloaded", target: docId });
    }

    // Private-store object: issue a short-lived, object-scoped signed URL AFTER the
    // authorization above and redirect to it. The raw store URL is never returned.
    const signed = await signedReadUrl(doc.blobUrl, { download: !inline });
    if (signed) {
      return NextResponse.redirect(signed.url, { status: 302, headers: { "cache-control": "private, no-store" } });
    }

    // Legacy object (pre-migration public store): stream the bytes through the proxy so the
    // raw store URL is never emitted. Unreachable once the migration completes.
    const streamed = await streamLegacyBlobResponse(doc.blobUrl, { download: !inline, mime: doc.mime, filename: doc.name });
    if (streamed) return streamed;

    // On neither store (or unreadable): fail closed — never leak an unrecognized URL.
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  } catch (e) {
    return errorResponse(e);
  }
}
