import { NextResponse } from "next/server";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { approvalDecisionSchema } from "@/lib/validation/schemas";
import { listPendingApprovals, decideApproval } from "@/lib/domain/approvals";

export const runtime = "nodejs";

/** Pending HITL approvals (agent-proposed CRM writes). Requires CreateRecord. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireCapability(req, id, Capability.CreateRecord);
    return NextResponse.json({ approvals: await listPendingApprovals(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Approve (apply) or reject a queued agent action. Requires CreateRecord. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = approvalDecisionSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    // CM2-B-B004: decideApproval re-checks ctx.role against the action's required
    // capability and blocks self-approval of high-risk actions (throws GuardError 403).
    const result = await decideApproval(id, parsed.data.approvalId, ctx.sub, ctx.role, parsed.data.decision);
    if (!result.ok) return NextResponse.json({ error: result.error ?? "failed" }, { status: 409 });
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
