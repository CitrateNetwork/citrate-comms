/**
 * Documents repository (metadata read for the CRM record file). Upload + RAG land in
 * AGENTS-S4 / CRM-D4; D1 just lists what's attached to a record. Extracted text is
 * encrypted (`text_enc`); only metadata is surfaced here.
 */
import { and, desc, eq, isNotNull, cosineDistance } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { documents, documentChunks } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { embed, embedOne } from "@/lib/ai/embeddings";
import { recordActivity } from "./crm-activity";

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

// ── Ingest: parse → chunk → embed (COMMS-AGENTS S4) ──────────────────────────

/** Extract text from a file buffer by type. Text formats inline; PDF via unpdf;
 *  unsupported types (e.g. docx) return null → stored as metadata-only. */
async function extractDocText(name: string, mime: string | null, buf: Buffer): Promise<string | null> {
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

const CHUNK_SIZE = 1200;
const CHUNK_OVERLAP = 150;
const MAX_CHUNKS = 500;

function chunkText(text: string): string[] {
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean) return [];
  const out: string[] = [];
  for (let i = 0; i < clean.length && out.length < MAX_CHUNKS; i += CHUNK_SIZE - CHUNK_OVERLAP) {
    out.push(clean.slice(i, i + CHUNK_SIZE));
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
  const text = args.text ?? (args.buffer ? await extractDocText(args.name, args.mime, args.buffer) : null);
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

  let chunks = 0;
  if (text) {
    const parts = chunkText(text);
    if (parts.length > 0) {
      const vecs = await embed(parts).catch(() => null);
      await db().insert(documentChunks).values(
        parts.map((t, i) => ({
          workspaceId: args.workspaceId,
          documentId,
          ord: i,
          textEnc: encryptField(args.workspaceId, t),
          embedding: vecs?.[i] ?? null,
        })),
      );
      chunks = parts.length;
    }
  }

  const entity = args.scope.dealId ? "deal" : args.scope.accountId ? "account" : null;
  const recordId = args.scope.dealId ?? args.scope.accountId ?? null;
  if (entity && recordId) {
    await recordActivity({ workspaceId: args.workspaceId, entity, recordId, actorSub: args.uploadedBySub, input: { kind: "document_added" }, meta: { documentId } });
  }
  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.uploadedBySub, event: "document_ingested", target: documentId });
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
 *  fallback otherwise), with the source document name for citation. */
export async function retrieveChunks(
  workspaceId: string,
  query: string,
  opts: { scope?: DocScope; budget?: number } = {},
): Promise<RetrievedChunk[]> {
  const budget = Math.min(Math.max(opts.budget ?? 6, 1), 20);
  const sc = opts.scope ? scopeCol(opts.scope) : undefined;
  const where = sc
    ? and(eq(documentChunks.workspaceId, workspaceId), sc)
    : eq(documentChunks.workspaceId, workspaceId);

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
