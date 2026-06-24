import { NextResponse } from "next/server";
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { ownsAgentThread, listThreadMessages } from "@/lib/domain/agent-threads";

export const runtime = "nodejs";

/** Messages of one of the caller's own threads (CH-0 resume). Owner-scoped: you can only
 *  load a thread you started (org-wide viewing is CH-1). */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; threadId: string }> }) {
  try {
    const { id, threadId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await ownsAgentThread(id, ctx.sub, threadId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
    const messages = await listThreadMessages(id, threadId);
    return NextResponse.json({ messages });
  } catch (e) {
    return errorResponse(e);
  }
}
