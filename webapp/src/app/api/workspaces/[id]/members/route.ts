import { NextResponse } from "next/server";
import { z } from "zod";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { errorResponse, readJson } from "@/lib/http";
import { canGrant, type Role } from "@/lib/rbac/matrix";
import { roster, memberRow, changeRole, offboard } from "@/lib/domain/members";

export const runtime = "nodejs";

/** Full roster for the members screen. Any active member may view it. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await requireCapability(req, id, Capability.ReadChannel); // baseline membership read
    return NextResponse.json({ members: await roster(id) });
  } catch (e) {
    return errorResponse(e);
  }
}

const changeRoleSchema = z.object({
  sub: z.string().min(1),
  role: z.enum(["Admin", "Member", "Partner", "Guest"]),
});

/**
 * Change a member's role. Anti-escalation: the issuer must be entitled to grant
 * BOTH the member's current role and the new role (so an Admin can't promote to
 * Admin/Owner nor demote a peer Admin/Owner). The Owner role is never assigned here.
 */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.AssignRole);
    const parsed = changeRoleSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });

    const target = await memberRow(id, parsed.data.sub);
    if (!target) return NextResponse.json({ error: "not_found" }, { status: 404 });
    if (target.role === "Owner") return NextResponse.json({ error: "cannot_change_owner" }, { status: 403 });

    const newRole = parsed.data.role as Role;
    if (!canGrant(ctx.role, target.role) || !canGrant(ctx.role, newRole)) {
      return NextResponse.json({ error: "forbidden_role_change" }, { status: 403 });
    }

    await changeRole(id, parsed.data.sub, newRole, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}

const offboardSchema = z.object({ sub: z.string().min(1) });

/**
 * Offboard a member (forward-only — they lose future access, keep what they saw).
 * Guards: cannot offboard the workspace Owner; cannot offboard yourself; an Admin
 * cannot offboard a peer Admin/Owner (canGrant gate).
 */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const ctx = await requireCapability(req, id, Capability.RemoveMember);
    const parsed = offboardSchema.safeParse(await readJson(req));
    if (!parsed.success) return NextResponse.json({ error: "invalid" }, { status: 400 });
    if (parsed.data.sub === ctx.sub) return NextResponse.json({ error: "cannot_offboard_self" }, { status: 403 });

    const target = await memberRow(id, parsed.data.sub);
    if (!target) return NextResponse.json({ error: "not_found" }, { status: 404 });
    if (target.role === "Owner") return NextResponse.json({ error: "cannot_offboard_owner" }, { status: 403 });
    if (!canGrant(ctx.role, target.role)) return NextResponse.json({ error: "forbidden" }, { status: 403 });

    await offboard(id, parsed.data.sub, ctx.sub);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return errorResponse(e);
  }
}
