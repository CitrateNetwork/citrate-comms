import { NextResponse } from "next/server";
import { Capability, requireCapability, requireInternal } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { createProjectSchema } from "@/lib/validation/schemas";
import { listProjects, createProject } from "@/lib/domain/pm";
import { appendAudit } from "@/lib/audit/chain";

export const runtime = "nodejs";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireInternal(req, id);
    return NextResponse.json({ projects: await listProjects(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.CreateRecord);
    const parsed = createProjectSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    const project = await createProject(id, parsed.data.name);
    await appendAudit({ workspaceId: id, actorSub: ctx.sub, event: "project_created", target: project.id });
    return NextResponse.json({ project }, { status: 201 });
  } catch (e) {
    return errorResponse(e);
  }
}
