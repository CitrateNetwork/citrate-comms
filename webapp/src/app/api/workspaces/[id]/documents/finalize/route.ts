import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { documentFinalizeSchema } from "@/lib/validation/schemas";
import { ingestDocument, badDocScope, blobUrlBoundToOtherWorkspace } from "@/lib/domain/documents";
import { ingestTable } from "@/lib/domain/import-store";
import { isTabularFile, summarizeParsed, parseWorkbook } from "@/lib/domain/import-parse";
import { isAllowed, isParseable, MAX_PARSE_BYTES, workspaceBlobPrefix } from "@/lib/attachments";
import { isOwnPrivateBlobUrl } from "@/lib/security/blob-host";
import { readBlobBytes, blobPathname } from "@/lib/security/blob-signing";

export const runtime = "nodejs";
export const maxDuration = 120;

/**
 * Finalize a client-direct Blob upload: record the document and (for parseable doc types
 * within the parse cap) fetch it back, extract + encrypt text, and embed chunks for RAG.
 * Images/video are recorded as metadata only. Member+ (CreateRecord).
 *
 * Object binding (PBA-L3c-009 / ATT-HARDEN): the blob must be on this deployment's PRIVATE
 * store, under this workspace's `comms/<id>/` prefix, and not already referenced by another
 * workspace's document — so a caller cannot register (and then read/sign) another workspace's
 * object. Legacy public URLs are rejected here (new uploads are always private).
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = documentFinalizeSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const { blobUrl, name, mime, accountId, dealId, channelId } = parsed.data;

    // PBA-L3c-009: only ever record objects on THIS deployment's PRIVATE store — not any
    // other *.blob.vercel-storage.com host, and not a legacy public object (new uploads are
    // private). An attacker's own store, or another workspace's object, is refused.
    if (!isOwnPrivateBlobUrl(blobUrl)) return NextResponse.json({ error: "bad_host" }, { status: 400 });

    // ATT-HARDEN: the object must live under this workspace's prefix (client uploads and the
    // server put both write `comms/<id>/…`), and must not already be bound to another
    // workspace — which also covers legacy, unprefixed pathnames.
    const pathname = blobPathname(blobUrl);
    if (!pathname || !pathname.startsWith(workspaceBlobPrefix(id))) return NextResponse.json({ error: "bad_scope" }, { status: 400 });
    if (await blobUrlBoundToOtherWorkspace(id, blobUrl)) return NextResponse.json({ error: "bad_scope" }, { status: 400 });

    // PBA-L3c-027: file type allowlist + every scope id must be THIS workspace's (and the
    // uploader must be seated in a channel they attach to).
    if (!isAllowed(name, mime ?? null)) return NextResponse.json({ error: "unsupported_type" }, { status: 415 });
    const bad = await badDocScope(id, ctx.sub, { accountId: accountId ?? null, dealId: dealId ?? null, channelId: channelId ?? null });
    if (bad) return NextResponse.json({ error: bad }, { status: bad === "bad_scope" ? 400 : 404 });

    // Parseable docs (within the cap) → read + parse for RAG. Media → metadata only.
    // readBlobBytes authenticates to the private store (a plain fetch of a private object
    // 401s) and enforces the parse-size cap; text extraction stays best-effort.
    let buffer: Buffer | undefined;
    if (isParseable(name, mime ?? null)) {
      buffer = (await readBlobBytes(blobUrl, MAX_PARSE_BYTES)) ?? undefined;
    }

    // Tabular files (xlsx/csv/…) land as STRUCTURED ROWS (row store) so agents can
    // profile/query/import them — and RAG indexes only a compact schema summary
    // (no full-cell dump → no silent chunk-cap truncation). Non-tabular docs keep
    // the plain text→RAG path.
    const tabular = buffer !== undefined && isTabularFile(name, mime ?? null);
    let batch: { batchId: string; sheets: { id: string; name: string; rowCount: number; colCount: number }[] } | null = null;

    if (tabular && buffer) {
      const parsed = await parseWorkbook(buffer, name);
      const result = await ingestDocument({
        workspaceId: id,
        scope: { accountId: accountId ?? null, dealId: dealId ?? null, channelId: channelId ?? null },
        name,
        mime: mime ?? null,
        blobUrl,
        uploadedBySub: ctx.sub,
        text: summarizeParsed(parsed), // compact summary → RAG
      });
      batch = await ingestTable({ workspaceId: id, documentId: result.id, filename: name, mime: mime ?? null, buffer, bySub: ctx.sub, parsed });
      return NextResponse.json({ document: { id: result.id, name }, chunks: result.chunks, table: batch }, { status: 201 });
    }

    const result = await ingestDocument({
      workspaceId: id,
      scope: { accountId: accountId ?? null, dealId: dealId ?? null, channelId: channelId ?? null },
      name,
      mime: mime ?? null,
      blobUrl,
      uploadedBySub: ctx.sub,
      buffer,
    });
    return NextResponse.json({ document: { id: result.id, name }, chunks: result.chunks }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
