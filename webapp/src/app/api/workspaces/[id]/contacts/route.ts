/**
 * GET  /api/workspaces/[id]/contacts  — list contacts (any member).
 * POST /api/workspaces/[id]/contacts  — create a contact (CreateRecord capability).
 *
 * Mirrors the sibling `accounts` route against the already-present `createContact()`
 * in lib/domain/crm.ts. This route was the ONE missing piece of the CRM write API
 * (XR-2, requested by citrate-press): `createContact` existed with no HTTP surface, so
 * a federation service could create accounts and deals but not contacts. Same guard
 * (requireCapability), same validation seam, same audit vocabulary as accounts/deals.
 */
import { NextResponse } from "next/server";
import { Capability, requireCapability, requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { createContactSchema } from "@/lib/validation/schemas";
import { listContacts, createContact } from "@/lib/domain/crm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireMember(req, id);
    return NextResponse.json({ contacts: await listContacts(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = createContactSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const contact = await createContact({
      workspaceId: id,
      name: parsed.data.name,
      title: parsed.data.title ?? null,
      accountId: parsed.data.accountId ?? null,
      ownerSub: ctx.sub,
    });
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "contact_created", target: contact.id });
    return NextResponse.json({ contact }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
