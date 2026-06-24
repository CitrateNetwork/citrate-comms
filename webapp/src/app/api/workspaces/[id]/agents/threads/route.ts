import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { listAgentThreads } from "@/lib/domain/agent-threads";

export const runtime = "nodejs";

/** The caller's own agent conversations (CH-0), optionally scoped to a persona. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const personaId = new URL(req.url).searchParams.get("personaId") ?? undefined;
    const threads = await listAgentThreads(id, ctx.sub, { personaId, limit: 50 });
    return NextResponse.json({ threads });
  } catch (e) {
    return errorResponse(e);
  }
}
