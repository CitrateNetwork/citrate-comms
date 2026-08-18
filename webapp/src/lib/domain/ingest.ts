/**
 * UDI orchestrator (PLANSET 10 / Phase 1) — the single ingest→write entry point.
 *
 * text/document → extract entities → stage as import_rows (identity mapping) →
 * confidence-gated import job. High-confidence rows auto-write via the job engine;
 * below-threshold rows are held and a SINGLE HITL review approval is enqueued.
 *
 * This module sits ABOVE approvals + import-engine (it imports both) so the engine
 * stays free of any approvals dependency — no import cycle.
 */
import { extractEntities, stageExtracted, extractionMapping, type DoExtract } from "./import-extract";
import { saveMapping, createImportJob, runImportSlice, type JobProgress } from "./import-engine";
import { enqueueApproval } from "./approvals";
import { getDocumentText } from "./documents";
import { getSettings } from "./settings";

export interface IngestSummary {
  source: "json" | "model";
  extracted: number;
  autoWrite: number;
  held: number;
  jobId: string | null;
  reviewApprovalId: string | null;
  progress: JobProgress | null;
  note: string;
}

async function threshold(workspaceId: string): Promise<number> {
  const s = await getSettings(workspaceId);
  const t = s.ingest?.autoWriteConfidence;
  return typeof t === "number" && t >= 0 && t <= 1 ? t : 0.85;
}

/** Ingest a free-form text block (or JSON) into the CRM, confidence-gated. */
export async function ingestText(args: {
  workspaceId: string;
  text: string;
  bySub: string;
  sourceName?: string;
  documentId?: string | null;
  hint?: string;
  /** Test seam: inject the model call. */
  doExtract?: DoExtract;
}): Promise<IngestSummary> {
  const minConfidence = await threshold(args.workspaceId);
  const ex = await extractEntities(args.text, { hint: args.hint, doExtract: args.doExtract });

  if (ex.records.length === 0) {
    return {
      source: ex.source,
      extracted: 0,
      autoWrite: 0,
      held: 0,
      jobId: null,
      reviewApprovalId: null,
      progress: null,
      note: ex.error ? `Extraction failed (${ex.error}); nothing written.` : "No CRM records found in the source.",
    };
  }

  const staged = await stageExtracted({
    workspaceId: args.workspaceId,
    records: ex.records,
    sourceName: args.sourceName ?? "ingest",
    documentId: args.documentId ?? null,
    bySub: args.bySub,
    threshold: minConfidence,
  });

  // Identity mapping is pre-approved (columns are already canonical CRM slots).
  const mappingId = await saveMapping({ workspaceId: args.workspaceId, sheetId: staged.sheetId, spec: extractionMapping(), bySub: args.bySub, approved: true });

  // Structured sources (JSON) carry no confidence → write everything (minConfidence
  // only bites model-extracted rows, which set a real confidence value).
  const jobId = await createImportJob({ workspaceId: args.workspaceId, sheetId: staged.sheetId, mappingId, bySub: args.bySub, minConfidence: ex.source === "model" ? minConfidence : null });
  const progress = await runImportSlice(args.workspaceId, jobId);

  // One HITL review for all below-threshold rows (approving it flushes them).
  let reviewApprovalId: string | null = null;
  if (staged.hold > 0) {
    const { approvalId } = await enqueueApproval({
      workspaceId: args.workspaceId,
      tool: "crm.ingest",
      requestedBySub: args.bySub,
      action: { kind: "crm.ingest_review", jobId, sheetName: args.sourceName ?? "ingest", held: staged.hold },
    });
    reviewApprovalId = approvalId;
  }

  return {
    source: ex.source,
    extracted: staged.total,
    autoWrite: staged.autoWrite,
    held: staged.hold,
    jobId,
    reviewApprovalId,
    progress,
    note:
      staged.hold > 0
        ? `${staged.autoWrite} record(s) written; ${staged.hold} low-confidence held for your review.`
        : `${staged.autoWrite} record(s) written.`,
  };
}

/** Ingest a stored document (PDF/text/docx/xlsx) by id. */
export async function ingestDocument(args: { workspaceId: string; documentId: string; bySub: string; hint?: string; doExtract?: DoExtract }): Promise<IngestSummary> {
  const doc = await getDocumentText(args.workspaceId, args.documentId);
  if (!doc) {
    return { source: "model", extracted: 0, autoWrite: 0, held: 0, jobId: null, reviewApprovalId: null, progress: null, note: "Document not found or no extractable text (scanned/image docs need OCR — out of scope in v1)." };
  }
  return ingestText({ workspaceId: args.workspaceId, text: doc.text, bySub: args.bySub, sourceName: doc.name, documentId: args.documentId, hint: args.hint, doExtract: args.doExtract });
}
