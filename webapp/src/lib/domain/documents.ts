/**
 * Documents repository (metadata read for the CRM record file). Upload + RAG land in
 * AGENTS-S4 / CRM-D4; D1 just lists what's attached to a record. Extracted text is
 * encrypted (`text_enc`); only metadata is surfaced here.
 */
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents } from "@/lib/db/schema";

export interface DocumentRow {
  id: string;
  name: string;
  mime: string | null;
  blobUrl: string;
  uploadedBySub: string;
  createdAt: string;
}

/** Documents attached to a record (by account/deal/channel scope). */
export async function listDocumentsForRecord(
  workspaceId: string,
  scope: { accountId?: string; dealId?: string; channelId?: string },
): Promise<DocumentRow[]> {
  const col = scope.accountId
    ? eq(documents.accountId, scope.accountId)
    : scope.dealId
      ? eq(documents.dealId, scope.dealId)
      : scope.channelId
        ? eq(documents.channelId, scope.channelId)
        : null;
  if (!col) return [];
  const rows = await db()
    .select({ id: documents.id, name: documents.name, mime: documents.mime, blobUrl: documents.blobUrl, uploadedBySub: documents.uploadedBySub, createdAt: documents.createdAt })
    .from(documents)
    .where(and(eq(documents.workspaceId, workspaceId), col))
    .orderBy(desc(documents.createdAt));
  return rows.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() }));
}
