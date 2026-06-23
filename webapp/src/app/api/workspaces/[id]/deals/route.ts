import { NextResponse } from "next/server";
import { Capability, requireCapability, requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { createDealSchema, moveDealSchema } from "@/lib/validation/schemas";
import { listDeals, createDeal, moveDealStage } from "@/lib/domain/crm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireMember(req, id);
    return NextResponse.json({ deals: await listDeals(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = createDealSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const deal = await createDeal({
      workspaceId: id,
      accountId: parsed.data.accountId,
      name: parsed.data.name,
      valueMinor: parsed.data.valueMinor,
      ownerSub: ctx.sub,
    });
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "deal_created", target: deal.id });
    return NextResponse.json({ deal }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Move a deal to a new pipeline stage. */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = moveDealSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await moveDealStage(id, parsed.data.dealId, parsed.data.stage);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "deal_stage_changed", target: `${parsed.data.dealId}:${parsed.data.stage}` });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
