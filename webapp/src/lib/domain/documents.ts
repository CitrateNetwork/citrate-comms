/**
 * Documents repository (metadata read for the CRM record file). Upload + RAG land in
 * AGENTS-S4 / CRM-D4; D1 just lists what's attached to a record. Extracted text is
 * encrypted (`text_enc`); only metadata is surfaced here.
 */
import { and, desc, eq, inArray, isNotNull, isNull, or, sql, cosineDistance, type SQL } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, documentChunks, channelMembers, messageAttachments, messages } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { embed, embedOne } from "@/lib/ai/embeddings";
import { recordActivity } from "./crm-activity";
import { recordExists } from "./crm";

export interface DocumentRow {
  id: string;
  name: string;
  mime: string | null;
  blobUrl: string;
  uploadedBySub: string;
  createdAt: string;
}

export interface DocScope {
  accountId?: string | null;
  dealId?: string | null;
  channelId?: string | null;
}

/**
 * Who is looking at documents (PBA-L3c-003). Visibility is decided per viewer, never per
 * workspace:
 *  - a document uploaded into a channel/DM (`channelId` set) is visible to that channel's
 *    members;
 *  - a document shared into a channel as a message attachment is visible to that
 *    channel's members;
 *  - a workspace-level document (`channelId` NULL) is visible to INTERNAL roles only
 *    (Partner/Guest never see workspace documents — PBA-L3c-002).
 * Every read path (download proxy, documents.list/read, RAG, artifact.attach, ingest)
 * applies this, so a private-channel or DM attachment never leaks workspace-wide.
 */
export interface DocViewer {
  sub: string;
  /** Holds ReadWorkspace (Owner/Admin/Member/Agent). */
  internal: boolean;
}

/** SQL predicate over `documents` that is true iff `viewer` may see the row. */
export function documentVisibleTo(workspaceId: string, viewer: DocViewer): SQL {
  const inMyChannel = sql`${documents.channelId} IN (SELECT ${channelMembers.channelId} FROM ${channelMembers} WHERE ${channelMembers.workspaceId} = ${workspaceId} AND ${channelMembers.sub} = ${viewer.sub})`;
  const sharedIntoMyChannel = sql`${documents.id} IN (SELECT ${messageAttachments.documentId} FROM ${messageAttachments} INNER JOIN ${messages} ON ${messages.id} = ${messageAttachments.messageId} INNER JOIN ${channelMembers} ON ${channelMembers.channelId} = ${messages.channelId} WHERE ${messageAttachments.workspaceId} = ${workspaceId} AND ${messages.workspaceId} = ${workspaceId} AND ${channelMembers.sub} = ${viewer.sub})`;
  const parts: SQL[] = [inMyChannel, sharedIntoMyChannel];
  if (viewer.internal) parts.unshift(isNull(documents.channelId));
  return or(...parts)!;
}

/** A single document the viewer may see, or null (absent OR not visible). */
export async function getVisibleDocument(workspaceId: string, id: string, viewer: DocViewer): Promise<DocumentRow | null> {
  const [r] = await db()
    .select({ id: documents.id, name: documents.name, mime: documents.mime, blobUrl: documents.blobUrl, uploadedBySub: documents.uploadedBySub, createdAt: documents.createdAt })
    .from(documents)
    .where(and(eq(documents.workspaceId, workspaceId), eq(documents.id, id), documentVisibleTo(workspaceId, viewer)))
    .limit(1);
  return r ? { ...r, createdAt: r.createdAt.toISOString() } : null;
}

/**
 * Validate a document's scope ids before insert (PBA-L3c-027): the account/deal must be
 * records of this workspace and a channel must be this workspace's AND seat the uploader.
 * Returns an error code, or null when the scope is valid.
 */
export async function badDocScope(
  workspaceId: string,
  uploaderSub: string,
  scope: { accountId: string | null; dealId: string | null; channelId: string | null },
): Promise<"not_found" | "bad_scope" | null> {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  for (const v of [scope.accountId, scope.dealId, scope.channelId]) if (v && !uuid.test(v)) return "bad_scope";
  if (scope.accountId && !(await recordExists(workspaceId, "account", scope.accountId))) return "not_found";
  if (scope.dealId && !(await recordExists(workspaceId, "deal", scope.dealId))) return "not_found";
  if (scope.channelId) {
    const [seat] = await db()
      .select({ sub: channelMembers.sub })
      .from(channelMembers)
      .where(and(eq(channelMembers.workspaceId, workspaceId), eq(channelMembers.channelId, scope.channelId), eq(channelMembers.sub, uploaderSub)))
      .limit(1);
    if (!seat) return "bad_scope";
  }
  return null;
}

/** The subset of `ids` that are documents of `workspaceId` visible to `viewer`. */
export async function visibleDocumentIds(workspaceId: string, ids: string[], viewer: DocViewer): Promise<Set<string>> {
  const uuids = ids.filter((i) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(i));
  if (uuids.length === 0) return new Set();
  const rows = await db()
    .select({ id: documents.id })
    .from(documents)
    .where(and(eq(documents.workspaceId, workspaceId), inArray(documents.id, uuids), documentVisibleTo(workspaceId, viewer)));
  return new Set(rows.map((r) => r.id));
}

/** A single document (workspace-scoped, NOT viewer-scoped) — internal use only; every
 *  caller-facing read goes through getVisibleDocument. */
export async function getDocument(workspaceId: string, id: string): Promise<DocumentRow | null> {
  const [r] = await db()
    .select({ id: documents.id, name: documents.name, mime: documents.mime, blobUrl: documents.blobUrl, uploadedBySub: documents.uploadedBySub, createdAt: documents.createdAt })
    .from(documents)
    .where(and(eq(documents.workspaceId, workspaceId), eq(documents.id, id)))
    .limit(1);
  return r ? { ...r, createdAt: r.createdAt.toISOString() } : null;
}

/**
 * Documents attached to a record (by account/deal/channel scope), as `viewer` may see them
 * (verifier V-003b): a file uploaded into a DM/private channel that is ALSO linked to an
 * account/deal stays invisible to non-participants on the record page. The raw Blob URL
 * never leaves the server — `blobUrl` carries the access-controlled inline proxy URL
 * ("" when there is no stored original).
 */
export async function listDocumentsForRecord(
  workspaceId: string,
  scope: { accountId?: string; dealId?: string; channelId?: string },
  viewer: DocViewer,
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
    .where(and(eq(documents.workspaceId, workspaceId), col, documentVisibleTo(workspaceId, viewer)))
    .orderBy(desc(documents.createdAt));
  return rows.map((r) => ({
    ...r,
    blobUrl: r.blobUrl ? `/api/workspaces/${workspaceId}/documents/${r.id}/download?inline=1` : "",
    createdAt: r.createdAt.toISOString(),
  }));
}

/** Documents in a workspace that `viewer` may see (newest first, bounded) — for agent
 *  artifact discovery. Viewer-scoped (PBA-L3c-003): private-channel/DM files are absent
 *  for non-participants. */
export async function listDocuments(workspaceId: string, viewer: DocViewer, limit = 50): Promise<DocumentRow[]> {
  const rows = await db()
    .select({ id: documents.id, name: documents.name, mime: documents.mime, blobUrl: documents.blobUrl, uploadedBySub: documents.uploadedBySub, createdAt: documents.createdAt })
    .from(documents)
    .where(and(eq(documents.workspaceId, workspaceId), documentVisibleTo(workspaceId, viewer)))
    .orderBy(desc(documents.createdAt))
    .limit(Math.min(Math.max(limit, 1), 200));
  return rows.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() }));
}

// ── Ingest: parse → chunk → embed (COMMS-AGENTS S4) ──────────────────────────

/** Extract text from a file buffer by type. Text formats inline; PDF via unpdf;
 *  unsupported types (e.g. docx) return null → stored as metadata-only. */
export async function extractDocText(name: string, mime: string | null, buf: Buffer): Promise<string | null> {
  const lower = name.toLowerCase();
  if ((mime && mime.startsWith("text/")) || /\.(txt|md|markdown|csv|tsv|json|log)$/.test(lower)) {
    return buf.toString("utf8");
  }
  if (mime === "application/pdf" || lower.endsWith(".pdf")) {
    try {
      const { getDocumentProxy, extractText } = await import("unpdf");
      const pdf = await getDocumentProxy(new Uint8Array(buf));
      const r = await extractText(pdf, { mergePages: true });
      return Array.isArray(r.text) ? r.text.join("\n") : r.text;
    } catch {
      return null;
    }
  }
  if (lower.endsWith(".xlsx") || lower.endsWith(".xls") || mime === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") {
    try {
      const XLSX = await import("xlsx");
      const wb = XLSX.read(buf, { type: "buffer" });
      return wb.SheetNames.map((n) => `# ${n}\n${XLSX.utils.sheet_to_csv(wb.Sheets[n]!)}`).join("\n\n");
    } catch {
      return null;
    }
  }
  if (lower.endsWith(".docx") || mime === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
    try {
      const mammoth = await import("mammoth");
      const r = await mammoth.extractRawText({ buffer: buf });
      return r.value;
    } catch {
      return null;
    }
  }
  return null; // images/video/other — stored as metadata only (no RAG text)
}

/** Fetch a stored document's blob and extract its text (UDI ingest source).
 *  Returns null if the doc is missing, unreachable, or an unsupported type. */
export async function getDocumentText(workspaceId: string, id: string, viewer: DocViewer): Promise<{ name: string; text: string } | null> {
  const doc = await getVisibleDocument(workspaceId, id, viewer);
  if (!doc?.blobUrl) return null;
  try {
    const res = await fetch(doc.blobUrl);
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    const text = await extractDocText(doc.name, doc.mime, buf);
    return text && text.trim() ? { name: doc.name, text } : null;
  } catch {
    return null;
  }
}

const CHUNK_SIZE = 1200;
const CHUNK_OVERLAP = 150;
// Raised from 500: tabular files no longer take this path (they go to the row store
// with a compact summary), so the remaining prose/PDF docs shouldn't silently lose
// their tail. If a doc STILL exceeds this, we log it rather than drop it silently.
const MAX_CHUNKS = 2000;

function chunkText(text: string): string[] {
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean) return [];
  const out: string[] = [];
  for (let i = 0; i < clean.length && out.length < MAX_CHUNKS; i += CHUNK_SIZE - CHUNK_OVERLAP) {
    out.push(clean.slice(i, i + CHUNK_SIZE));
  }
  const wouldBe = Math.ceil(clean.length / (CHUNK_SIZE - CHUNK_OVERLAP));
  if (wouldBe > MAX_CHUNKS) {
    console.warn(`[ingestDocument] text truncated for RAG: ${out.length}/${wouldBe} chunks indexed (${clean.length} chars). Large tabular data should use the row store.`);
  }
  return out;
}

export interface IngestArgs {
  workspaceId: string;
  scope: DocScope;
  name: string;
  mime: string | null;
  blobUrl: string;
  uploadedBySub: string;
  /** Either a raw file buffer (parsed by type) or already-extracted text (generated docs). */
  buffer?: Buffer;
  text?: string;
}

/** Store a document + its embedded chunks. Embeddings are best-effort (null until the
 *  gateway serves bge); RAG falls back to lexical until then. */
export async function ingestDocument(args: IngestArgs): Promise<{ id: string; chunks: number }> {
  // Text extraction is best-effort and must never fail the upload (extractDocText already
  // catches per-format, but guard the whole step regardless).
  let text: string | null = null;
  try {
    text = args.text ?? (args.buffer ? await extractDocText(args.name, args.mime, args.buffer) : null);
  } catch {
    text = null;
  }

  // The document record is the part that MUST succeed — once the blob is up, the file is
  // recorded + downloadable. If this insert throws, the caller surfaces a real failure.
  const [doc] = await db()
    .insert(documents)
    .values({
      workspaceId: args.workspaceId,
      accountId: args.scope.accountId ?? null,
      dealId: args.scope.dealId ?? null,
      channelId: args.scope.channelId ?? null,
      blobUrl: args.blobUrl,
      name: args.name,
      mime: args.mime,
      textEnc: text ? encryptField(args.workspaceId, text) : null,
      uploadedBySub: args.uploadedBySub,
    })
    .returning({ id: documents.id });
  const documentId = doc!.id;

  // Everything after the doc row is best-effort RAG indexing — a failure here (embeddings,
  // a large chunk batch, pgvector) must NOT fail the upload. The doc is already stored.
  let chunks = 0;
  if (text) {
    try {
      const parts = chunkText(text);
      if (parts.length > 0) {
        const vecs = await embed(parts).catch(() => null);
        const rows = parts.map((t, i) => ({
          workspaceId: args.workspaceId,
          documentId,
          ord: i,
          textEnc: encryptField(args.workspaceId, t),
          embedding: vecs?.[i] ?? null,
        }));
        // Batch inserts so a long PDF (hundreds of 1024-dim vectors) can't blow the
        // statement/param ceiling and fail the whole upload.
        for (let i = 0; i < rows.length; i += 50) {
          await db().insert(documentChunks).values(rows.slice(i, i + 50));
        }
        chunks = parts.length;
      }
    } catch (e) {
      console.error("[ingestDocument] indexing failed (doc still stored):", e);
      chunks = 0;
    }
  }

  try {
    const entity = args.scope.dealId ? "deal" : args.scope.accountId ? "account" : null;
    const recordId = args.scope.dealId ?? args.scope.accountId ?? null;
    if (entity && recordId) {
      await recordActivity({ workspaceId: args.workspaceId, entity, recordId, actorSub: args.uploadedBySub, input: { kind: "document_added" }, meta: { documentId } });
    }
    await appendAudit({ workspaceId: args.workspaceId, actorSub: args.uploadedBySub, event: "document_ingested", target: documentId });
  } catch (e) {
    console.error("[ingestDocument] activity/audit failed (doc still stored):", e);
  }
  return { id: documentId, chunks };
}

// ── RAG retrieval (documents.read) ───────────────────────────────────────────

export interface RetrievedChunk {
  documentId: string;
  name: string;
  snippet: string;
}

const RETRIEVE_WINDOW = 800;

function scopeCol(scope: DocScope) {
  if (scope.dealId) return eq(documents.dealId, scope.dealId);
  if (scope.accountId) return eq(documents.accountId, scope.accountId);
  if (scope.channelId) return eq(documents.channelId, scope.channelId);
  return undefined;
}

function tokenize(s: string): Set<string> {
  return new Set(s.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/).filter((w) => w.length > 2));
}

/** Retrieve the most relevant document chunks (semantic when embeddings exist; lexical
 *  fallback otherwise), with the source document name for citation. Viewer-scoped
 *  (PBA-L3c-003): only chunks of documents `viewer` may see are candidates. */
export async function retrieveChunks(
  workspaceId: string,
  query: string,
  viewer: DocViewer,
  opts: { scope?: DocScope; budget?: number } = {},
): Promise<RetrievedChunk[]> {
  const budget = Math.min(Math.max(opts.budget ?? 6, 1), 20);
  const sc = opts.scope ? scopeCol(opts.scope) : undefined;
  const base = and(eq(documentChunks.workspaceId, workspaceId), eq(documents.workspaceId, workspaceId), documentVisibleTo(workspaceId, viewer));
  const where = sc ? and(base, sc) : base;

  const qVec = query ? await embedOne(query).catch(() => null) : null;
  if (qVec) {
    const rows = await db()
      .select({ documentId: documentChunks.documentId, name: documents.name, textEnc: documentChunks.textEnc })
      .from(documentChunks)
      .innerJoin(documents, eq(documentChunks.documentId, documents.id))
      .where(and(where, isNotNull(documentChunks.embedding)))
      .orderBy(cosineDistance(documentChunks.embedding, qVec))
      .limit(budget);
    if (rows.length > 0) return rows.map((r) => ({ documentId: r.documentId, name: r.name, snippet: safeDec(workspaceId, r.textEnc) }));
  }

  // Lexical fallback over a bounded window.
  const rows = await db()
    .select({ documentId: documentChunks.documentId, name: documents.name, textEnc: documentChunks.textEnc })
    .from(documentChunks)
    .innerJoin(documents, eq(documentChunks.documentId, documents.id))
    .where(where)
    .limit(RETRIEVE_WINDOW);
  const qTokens = tokenize(query ?? "");
  return rows
    .map((r) => {
      const snippet = safeDec(workspaceId, r.textEnc);
      const ct = tokenize(snippet);
      let hits = 0;
      for (const t of qTokens) if (ct.has(t)) hits++;
      return { documentId: r.documentId, name: r.name, snippet, score: qTokens.size ? hits / qTokens.size : 0 };
    })
    .filter((r) => qTokens.size === 0 || r.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, budget)
    .map(({ documentId, name, snippet }) => ({ documentId, name, snippet }));
}

function safeDec(workspaceId: string, enc: string): string {
  try {
    return decryptField(workspaceId, enc);
  } catch {
    return "";
  }
}
