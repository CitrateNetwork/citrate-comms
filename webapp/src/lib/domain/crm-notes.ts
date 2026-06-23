/**
 * CRM notes/journal timeline (COMMS-CRM-DEPTH §3). A typed, encrypted, chronological
 * entry stream per record (note|journal|call|meeting|email) + threaded comments. Adding
 * a note writes a value-free `note_added` activity row so the feed reflects it.
 */
import { and, asc, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmNotes, crmNoteComments } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { recordActivity } from "./crm-activity";
import { type CrmEntity, type CrmNoteType } from "./crm-enums";

export interface NoteRow {
  id: string;
  type: CrmNoteType;
  title: string | null;
  body: string;
  authorSub: string;
  byAgent: boolean;
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
}

function dec(workspaceId: string, enc: string | null): string {
  if (!enc) return "";
  try {
    return decryptField(workspaceId, enc);
  } catch {
    return "⚠︎ couldn't decrypt";
  }
}

/** Notes for a record — pinned first, then newest first. */
export async function listNotes(workspaceId: string, entity: CrmEntity, recordId: string): Promise<NoteRow[]> {
  const rows = await db()
    .select()
    .from(crmNotes)
    .where(and(eq(crmNotes.workspaceId, workspaceId), eq(crmNotes.entity, entity), eq(crmNotes.recordId, recordId)))
    .orderBy(desc(crmNotes.pinned), desc(crmNotes.createdAt));
  return rows.map((r) => ({
    id: r.id,
    type: r.type as CrmNoteType,
    title: r.titleEnc ? dec(workspaceId, r.titleEnc) : null,
    body: dec(workspaceId, r.bodyEnc),
    authorSub: r.authorSub,
    byAgent: r.byAgent,
    pinned: r.pinned,
    createdAt: r.createdAt.toISOString(),
    updatedAt: r.updatedAt.toISOString(),
  }));
}

export async function addNote(args: {
  workspaceId: string;
  entity: CrmEntity;
  recordId: string;
  type: CrmNoteType;
  title?: string | null;
  body: string;
  authorSub: string;
  byAgent?: boolean;
  personaId?: string | null;
}): Promise<NoteRow> {
  const [row] = await db()
    .insert(crmNotes)
    .values({
      workspaceId: args.workspaceId,
      entity: args.entity,
      recordId: args.recordId,
      type: args.type,
      titleEnc: args.title?.trim() ? encryptField(args.workspaceId, args.title.trim()) : null,
      bodyEnc: encryptField(args.workspaceId, args.body),
      authorSub: args.authorSub,
      byAgent: args.byAgent ?? false,
      personaId: args.personaId ?? null,
    })
    .returning();
  await recordActivity({
    workspaceId: args.workspaceId,
    entity: args.entity,
    recordId: args.recordId,
    actorSub: args.authorSub,
    byAgent: args.byAgent ?? false,
    input: { kind: "note_added", noteType: args.type },
    meta: { noteId: row!.id },
  });
  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.authorSub, event: "crm_note_added", target: `${args.entity}:${row!.id}` });
  return {
    id: row!.id,
    type: row!.type as CrmNoteType,
    title: args.title?.trim() || null,
    body: args.body,
    authorSub: row!.authorSub,
    byAgent: row!.byAgent,
    pinned: row!.pinned,
    createdAt: row!.createdAt.toISOString(),
    updatedAt: row!.updatedAt.toISOString(),
  };
}

export interface CommentRow {
  id: string;
  body: string;
  authorSub: string;
  byAgent: boolean;
  createdAt: string;
}

export async function listComments(workspaceId: string, noteId: string): Promise<CommentRow[]> {
  const rows = await db()
    .select()
    .from(crmNoteComments)
    .where(and(eq(crmNoteComments.workspaceId, workspaceId), eq(crmNoteComments.noteId, noteId)))
    .orderBy(asc(crmNoteComments.createdAt));
  return rows.map((r) => ({
    id: r.id,
    body: dec(workspaceId, r.bodyEnc),
    authorSub: r.authorSub,
    byAgent: r.byAgent,
    createdAt: r.createdAt.toISOString(),
  }));
}

export async function addComment(args: {
  workspaceId: string;
  noteId: string;
  body: string;
  authorSub: string;
  byAgent?: boolean;
}): Promise<void> {
  await db().insert(crmNoteComments).values({
    workspaceId: args.workspaceId,
    noteId: args.noteId,
    bodyEnc: encryptField(args.workspaceId, args.body),
    authorSub: args.authorSub,
    byAgent: args.byAgent ?? false,
  });
}

export async function setNotePinned(workspaceId: string, noteId: string, pinned: boolean): Promise<void> {
  await db()
    .update(crmNotes)
    .set({ pinned, updatedAt: new Date() })
    .where(and(eq(crmNotes.workspaceId, workspaceId), eq(crmNotes.id, noteId)));
}
