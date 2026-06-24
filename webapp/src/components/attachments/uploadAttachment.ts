"use client";

/**
 * Client helper: upload one file straight to Vercel Blob (via the auth'd token route) and
 * finalize it (record + RAG-index). Shared by the record DropZone, the channel composer, and
 * the agent-chat composer. Returns the finalized document or an error.
 */
import { upload } from "@vercel/blob/client";
import { isAllowed, maxBytesFor } from "@/lib/attachments";

export interface UploadedDoc {
  id: string;
  name: string;
  mime: string | null;
}
interface Scope {
  accountId?: string;
  dealId?: string;
  channelId?: string;
}

export async function uploadAttachment(
  workspaceId: string,
  scope: Scope,
  file: File,
): Promise<{ ok: true; doc: UploadedDoc } | { ok: false; error: string }> {
  if (!isAllowed(file.name, file.type)) return { ok: false, error: "Unsupported type" };
  if (file.size > maxBytesFor(file.name, file.type)) return { ok: false, error: "Too large" };
  let blobUrl: string;
  try {
    const blob = await upload(file.name, file, {
      access: "public",
      handleUploadUrl: `/api/workspaces/${workspaceId}/documents/upload-token`,
      clientPayload: JSON.stringify(scope),
    });
    blobUrl = blob.url;
  } catch (e) {
    // Most common cause: no Vercel Blob store linked (BLOB_READ_WRITE_TOKEN unset).
    const msg = (e as Error)?.message ?? "";
    return { ok: false, error: /token|blob|store|not\s*found/i.test(msg) ? "Storage not configured — link a Vercel Blob store" : `Storage upload failed${msg ? `: ${msg}` : ""}` };
  }
  try {
    const r = await fetch(`/api/workspaces/${workspaceId}/documents/finalize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ blobUrl, name: file.name, mime: file.type, ...scope }),
    });
    if (!r.ok) {
      const body = (await r.json().catch(() => ({}))) as { error?: string };
      return { ok: false, error: `Finalize failed (${r.status}${body.error ? `: ${body.error}` : ""})` };
    }
    const j = (await r.json()) as { document: { id: string; name: string } };
    return { ok: true, doc: { id: j.document.id, name: file.name, mime: file.type || null } };
  } catch (e) {
    return { ok: false, error: `Finalize error: ${(e as Error)?.message ?? "unknown"}` };
  }
}
