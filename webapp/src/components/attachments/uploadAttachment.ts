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
  try {
    const blob = await upload(file.name, file, {
      access: "public",
      handleUploadUrl: `/api/workspaces/${workspaceId}/documents/upload-token`,
      clientPayload: JSON.stringify(scope),
    });
    const r = await fetch(`/api/workspaces/${workspaceId}/documents/finalize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ blobUrl: blob.url, name: file.name, mime: file.type, ...scope }),
    });
    if (!r.ok) return { ok: false, error: "Upload failed" };
    const j = (await r.json()) as { document: { id: string; name: string } };
    return { ok: true, doc: { id: j.document.id, name: file.name, mime: file.type || null } };
  } catch {
    return { ok: false, error: "Upload failed" };
  }
}
