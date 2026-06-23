import { NextResponse } from "next/server";
import { z } from "zod";
import { Capability, requireCapability, requireMember } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { addAgentSchema } from "@/lib/validation/schemas";
import { listAgents, addAgent, setAgentEnabled } from "@/lib/domain/agents";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireMember(req, id);
    return NextResponse.json({ agents: await listAgents(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.AddAgent);
    const parsed = addAgentSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const agent = await addAgent({ workspaceId: id, name: parsed.data.name, purpose: parsed.data.purpose ?? null, sponsorSub: ctx.sub });
    return NextResponse.json({ agent }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}

const toggleSchema = z.object({ agentId: z.string().uuid(), enabled: z.boolean() });

export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.AddAgent);
    const parsed = toggleSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    await setAgentEnabled(id, parsed.data.agentId, parsed.data.enabled, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
