import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { documentFinalizeSchema } from "@/lib/validation/schemas";
import { recordExists } from "@/lib/domain/crm";
import { ingestDocument } from "@/lib/domain/documents";
import { ingestTable } from "@/lib/domain/import-store";
import { isTabularFile, summarizeParsed, parseWorkbook } from "@/lib/domain/import-parse";
import { isParseable, MAX_PARSE_BYTES } from "@/lib/attachments";

export const runtime = "nodejs";
export const maxDuration = 120;

/**
 * Finalize a client-direct Blob upload: record the document and (for parseable doc types
 * within the parse cap) fetch it back, extract + encrypt text, and embed chunks for RAG.
 * Images/video are recorded as metadata only. Member+ (CreateRecord).
 *
 * SSRF guard: only Vercel Blob URLs are fetched server-side.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = documentFinalizeSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const { blobUrl, name, mime, accountId, dealId, channelId } = parsed.data;

    // Only ever fetch Vercel Blob URLs (no arbitrary server-side fetch).
    let host = "";
    try {
      host = new URL(blobUrl).hostname;
    } catch {
      return NextResponse.json({ error: "bad_url" }, { status: 400 });
    }
    if (!host.endsWith(".blob.vercel-storage.com")) return NextResponse.json({ error: "bad_host" }, { status: 400 });

    if (accountId && !(await recordExists(id, "account", accountId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
    if (dealId && !(await recordExists(id, "deal", dealId))) return NextResponse.json({ error: "not_found" }, { status: 404 });

    // Parseable docs (within the cap) → fetch + parse for RAG. Media → metadata only.
    let buffer: Buffer | undefined;
    if (isParseable(name, mime ?? null)) {
      try {
        const r = await fetch(blobUrl, { cache: "no-store" });
        if (r.ok) {
          const len = Number(r.headers.get("content-length") ?? 0);
          if (len <= MAX_PARSE_BYTES) buffer = Buffer.from(await r.arrayBuffer());
        }
      } catch {
        /* parse is best-effort — store the doc regardless */
      }
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
