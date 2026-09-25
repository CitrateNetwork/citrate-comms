import { NextResponse } from "next/server";
import { Capability, requireCapability, requireInternal } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";

export const runtime = "nodejs";

/**
 * List the workspace's agent personas. Seeds the three org-default templates on first
 * read so the agent panel always has personas to pick (idempotent). Any active member
 * may list; seeding is attributed to the caller.
 */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireInternal(req, id);
    let personas = await listPersonas(id);
    if (personas.length === 0) {
      await seedDefaultPersonas(id, ctx.sub);
      personas = await listPersonas(id);
    }
    return NextResponse.json({ personas });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Re-seed missing default templates (Owner/Admin). Idempotent on persona key. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.ManageWorkspace);
    const seeded = await seedDefaultPersonas(id, ctx.sub);
    return NextResponse.json({ seeded, personas: await listPersonas(id) });
  } catch (e) {
    return errorResponse(e);
  }
}
