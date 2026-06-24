import { NextResponse } from "next/server";
import { requireMember, GuardError } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { canConfigurePersona, listResources, addResource, type ResourceKind } from "@/lib/domain/agent-config";

export const runtime = "nodejs";

const KINDS: ResourceKind[] = ["text", "link", "document"];

/** CFG resources for a persona. Admin OR a delegated configurer. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await canConfigurePersona(id, ctx.sub, ctx.role, personaId))) throw new GuardError(403, "not authorized");
    return NextResponse.json({ resources: await listResources(id, personaId) });
  } catch (e) {
    return errorResponse(e);
  }
}

/** Add a resource (text | link | document). Admin OR a delegated configurer. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string; personaId: string }> }) {
  try {
    const { id, personaId } = await params;
    const ctx = await requireMember(req, id);
    if (!(await canConfigurePersona(id, ctx.sub, ctx.role, personaId))) throw new GuardError(403, "not authorized");
    const body = (await readJson(req)) as { kind?: string; title?: string; content?: string; url?: string; documentId?: string };
    const kind = body.kind as ResourceKind;
    if (!KINDS.includes(kind)) return NextResponse.json({ error: "bad_kind" }, { status: 400 });
    const resourceId = await addResource(
      id,
      personaId,
      { kind, title: String(body.title ?? ""), content: body.content, url: body.url, documentId: body.documentId },
      ctx.sub,
    );
    if (!resourceId) return NextResponse.json({ error: "invalid_resource" }, { status: 400 });
    return NextResponse.json({ ok: true, resourceId }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
