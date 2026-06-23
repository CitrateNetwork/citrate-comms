/**
 * The witness Ledger — the signature feature. A message can be "witnessed" as a
 * decision / commitment / resolved record, lifted into a per-channel ledger as an
 * attributed, hashed, auditable entry. Each witness writes a BLAKE3 record hash and
 * appends to the workspace audit chain. Text is encrypted at rest per-workspace.
 */
import { blake3 } from "@noble/hashes/blake3";
import { bytesToHex } from "@noble/hashes/utils";
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { ledgerEntries } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";

export type WitnessKind = "decision" | "commitment" | "resolved";

export interface LedgerRow {
  id: string;
  channelId: string;
  kind: WitnessKind;
  text: string;
  bySub: string;
  ownerSub: string | null;
  due: string | null;
  status: "open" | "done";
  proposedByAgent: boolean;
  recordHash: string;
  createdAt: string;
}

function recordHash(workspaceId: string, channelId: string, kind: string, text: string, bySub: string): string {
  const blob = ["citrate-comms-web/ledger/v1", workspaceId, channelId, kind, bySub, text].join(" ");
  return bytesToHex(blake3(new TextEncoder().encode(blob)));
}

export interface WitnessInput {
  workspaceId: string;
  channelId: string;
  sourceMessageId?: string | null;
  kind: WitnessKind;
  text: string;
  bySub: string;
  ownerSub?: string | null;
  due?: Date | null;
  proposedByAgent?: boolean;
}

/** Record a witness entry and chain it into the workspace audit log. */
export async function witness(input: WitnessInput): Promise<LedgerRow> {
  const hash = recordHash(input.workspaceId, input.channelId, input.kind, input.text, input.bySub);
  const [row] = await db()
    .insert(ledgerEntries)
    .values({
      workspaceId: input.workspaceId,
      channelId: input.channelId,
      sourceMessageId: input.sourceMessageId ?? null,
      kind: input.kind,
      textEnc: encryptField(input.workspaceId, input.text),
      bySub: input.bySub,
      ownerSub: input.ownerSub ?? null,
      due: input.due ?? null,
      proposedByAgent: input.proposedByAgent ?? false,
      recordHash: hash,
    })
    .returning();
  await appendAudit({
    workspaceId: input.workspaceId,
    actorSub: input.bySub,
    event: `witness_${input.kind}`,
    target: row!.id,
  });
  return decode(input.workspaceId, row!);
}

function decode(workspaceId: string, r: typeof ledgerEntries.$inferSelect): LedgerRow {
  return {
    id: r.id,
    channelId: r.channelId,
    kind: r.kind as WitnessKind,
    text: tryDecrypt(workspaceId, r.textEnc),
    bySub: r.bySub,
    ownerSub: r.ownerSub,
    due: r.due ? r.due.toISOString() : null,
    status: r.status as "open" | "done",
    proposedByAgent: r.proposedByAgent,
    recordHash: r.recordHash,
    createdAt: r.createdAt.toISOString(),
  };
}

function tryDecrypt(workspaceId: string, packed: string): string {
  try {
    return decryptField(workspaceId, packed);
  } catch {
    return "⚠︎ couldn't decrypt";
  }
}

/** Ledger entries for a channel, newest first. */
export async function listLedger(workspaceId: string, channelId: string): Promise<LedgerRow[]> {
  const rows = await db()
    .select()
    .from(ledgerEntries)
    .where(and(eq(ledgerEntries.workspaceId, workspaceId), eq(ledgerEntries.channelId, channelId)))
    .orderBy(desc(ledgerEntries.createdAt));
  return rows.map((r) => decode(workspaceId, r));
}

/** Mark a commitment resolved (status → done). */
export async function resolveLedgerEntry(workspaceId: string, id: string, actorSub: string): Promise<void> {
  await db()
    .update(ledgerEntries)
    .set({ status: "done" })
    .where(and(eq(ledgerEntries.workspaceId, workspaceId), eq(ledgerEntries.id, id)));
  await appendAudit({ workspaceId, actorSub, event: "witness_resolved_done", target: id });
}
