import { NextResponse } from "next/server";
import { Capability, requireCapability, requireInternal } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { createAccountSchema } from "@/lib/validation/schemas";
import { listAccounts, createAccount } from "@/lib/domain/crm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireInternal(req, id);
    return NextResponse.json({ accounts: await listAccounts(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = createAccountSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const account = await createAccount(id, parsed.data.name, parsed.data.domain ?? null, ctx.sub);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "account_created", target: account.id });
    return NextResponse.json({ account }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
