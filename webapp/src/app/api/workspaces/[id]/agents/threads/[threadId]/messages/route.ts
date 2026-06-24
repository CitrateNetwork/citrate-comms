import { NextResponse } from "next/server";
import { requireMember, assertCan, Capability } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { ownsAgentThread, threadInWorkspace, listThreadMessages } from "@/lib/domain/agent-threads";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

/** Messages of an agent thread. You can always read your own (CH-0 resume). Owner/Admin
 *  (ManageWorkspace) may read any thread in the workspace (CH-1 org-wide view) — and that
 *  read is itself audited, so oversight is on the record. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; threadId: string }> }) {
  try {
    const { id, threadId } = await params;
    const ctx = await requireMember(req, id);
    const isOwner = await ownsAgentThread(id, ctx.sub, threadId);
    if (!isOwner) {
      // Admin override: must hold ManageWorkspace AND the thread must exist in this workspace.
      assertCan(ctx, Capability.ManageWorkspace);
      if (!(await threadInWorkspace(id, threadId))) return NextResponse.json({ error: "not_found" }, { status: 404 });
      await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "agent_thread_viewed", target: threadId });
    }
    const messages = await listThreadMessages(id, threadId);
    return NextResponse.json({ messages, readOnly: !isOwner });
  } catch (e) {
    return errorResponse(e);
  }
}
