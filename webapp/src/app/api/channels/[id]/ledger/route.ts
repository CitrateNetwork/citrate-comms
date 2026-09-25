import { NextResponse } from "next/server";
import { z } from "zod";
import { Capability, requireChannel } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { limit } from "@/lib/security/ratelimit";
import { hashId } from "@/lib/security/crypto";
import { witnessSchema } from "@/lib/validation/schemas";
import { channelWorkspace, isChannelMember } from "@/lib/domain/channels";
import { listLedger, witness, resolveLedgerEntry } from "@/lib/witness/ledger";

export const runtime = "nodejs";

/** List the witness ledger for a channel. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.ReadChannel, channelWorkspace, isChannelMember);
    return NextResponse.json({ ledger: await listLedger(ctx.workspaceId, id) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Witness a message → a ledger entry (decision/commitment/resolved). */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.PostMessage, channelWorkspace, isChannelMember);

    const rl = await limit(`witness:${hashId(ctx.sub)}:${id}`);
    if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429 });

    const parsed = witnessSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid", detail: parsed.error.flatten() }, { status: 400 });

    const entry = await witness({
      workspaceId: ctx.workspaceId,
      channelId: id,
      sourceMessageId: parsed.data.sourceMessageId ?? null,
      kind: parsed.data.kind,
      text: parsed.data.text,
      bySub: ctx.sub,
      ownerSub: parsed.data.ownerSub ?? null,
      due: parsed.data.due ? new Date(parsed.data.due) : null,
    });
    return NextResponse.json({ entry }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

const resolveSchema = z.object({ entryId: z.string().uuid() });

/** Mark a commitment resolved (status → done). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireChannel(req, id, Capability.PostMessage, channelWorkspace, isChannelMember);
    const parsed = resolveSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    if (!(await resolveLedgerEntry(ctx.workspaceId, id, parsed.data.entryId, ctx.sub))) {
      return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
