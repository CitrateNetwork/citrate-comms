import { NextResponse } from "next/server";
import { requireMember, Capability } from "@/lib/tenant/guard";
import { can } from "@/lib/rbac/matrix";
import { errorResponse } from "@/lib/http";
import { listWorkspaceThreads } from "@/lib/domain/agent-threads";

export const runtime = "nodejs";

/**
 * CH-1: the org-wide agent-conversation directory. Owner/Admin (ManageWorkspace) see every
 * member's saved chats; everyone else sees only their own. Filterable by persona and by
 * invoker. Incognito chats are never persisted, so they never appear here.
 */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireMember(req, id);
    const viewAll = can(ctx.role, Capability.ManageWorkspace);
    const url = new URL(req.url);
    const threads = await listWorkspaceThreads(id, ctx.sub, {
      viewAll,
      personaId: url.searchParams.get("personaId") ?? undefined,
      invokedBySub: url.searchParams.get("memberSub") ?? undefined,
      limit: 150,
    });
    return NextResponse.json({ threads, scope: viewAll ? "workspace" : "self" });
  } catch (e) {
    return errorResponse(e);
  }
}
