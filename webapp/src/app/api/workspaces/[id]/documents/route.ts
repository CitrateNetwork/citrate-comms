import { NextResponse } from "next/server";
import { put } from "@vercel/blob";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { ingestDocument, badDocScope } from "@/lib/domain/documents";
import { isAllowed } from "@/lib/attachments";

export const runtime = "nodejs";
export const maxDuration = 120;

const MAX_BYTES = 8 * 1024 * 1024; // 8 MB

/**
 * Upload a document to a record (account/deal) or channel. Stores the original at Vercel
 * Blob (unguessable URL) when a Blob token is configured; ALWAYS extracts + encrypts the
 * text and embeds chunks for RAG. Member+ (CreateRecord).
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);

    const form = await req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return NextResponse.json({ error: "no_file" }, { status: 400 });
    if (file.size > MAX_BYTES) return NextResponse.json({ error: "too_large", message: "Max 8 MB." }, { status: 413 });

    const accountId = (form.get("accountId") as string) || null;
    const dealId = (form.get("dealId") as string) || null;
    const channelId = (form.get("channelId") as string) || null;
    const name = file.name || "document";
    const mime = file.type || null;
    // PBA-L3c-027: file type allowlist + every scope id must be THIS workspace's (and the
    // uploader must be seated in a channel they attach to).
    if (!isAllowed(name, mime)) return NextResponse.json({ error: "unsupported_type" }, { status: 415 });
    const bad = await badDocScope(id, ctx.sub, { accountId, dealId, channelId });
    if (bad) return NextResponse.json({ error: bad }, { status: 400 });
    const buffer = Buffer.from(await file.arrayBuffer());

    // Store the original at Blob when configured; otherwise keep text-only (still RAG-able).
    let blobUrl = "";
    if (process.env.BLOB_READ_WRITE_TOKEN) {
      try {
        const blob = await put(`comms/${id}/${name}`, file, { access: "public", addRandomSuffix: true });
        blobUrl = blob.url;
      } catch {
        blobUrl = "";
      }
    }

    const result = await ingestDocument({
      workspaceId: id,
      scope: { accountId, dealId, channelId },
      name,
      mime,
      blobUrl,
      uploadedBySub: ctx.sub,
      buffer,
    });

    return NextResponse.json({ document: { id: result.id, name }, chunks: result.chunks, stored: Boolean(blobUrl) }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
