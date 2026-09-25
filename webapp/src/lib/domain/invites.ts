/**
 * Invite repository — email-primary onboarding. An invite stores only the SHA-256
 * of a high-entropy token (the raw token travels only in the emailed link, never
 * persisted), plus the target email, role, and expiry. Accepting an invite binds a
 * verified identity to the workspace at the granted role.
 *
 * Security model: the emailed link is a single-use bearer credential (possession proves
 * the person received that email). The signed-in identity that redeems it is NOT required
 * to match the invite email (see acceptInvite). Redemption is atomic: exactly one
 * identity can consume a token (PBA-L3c-023).
 */
import { randomBytes } from "node:crypto";
import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { invites, members, workspaces, channels, channelMembers } from "@/lib/db/schema";
import { hashToken } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import type { Role } from "@/lib/rbac/matrix";

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface PendingInvite {
  email: string;
  role: Role;
  workspaceId: string;
  workspaceName: string;
  invitedBySub: string;
  expiresAt: string;
  scopeChannelId: string | null;
}

export interface CreatedInvite {
  token: string; // returned ONCE to build the link; never stored raw
  email: string;
  role: Role;
  expiresAt: string;
}

/** Create (or refresh) an invite for an email at a role. Returns the raw token once. */
export async function createInvite(args: {
  workspaceId: string;
  email: string;
  role: Role;
  invitedBySub: string;
  scopeChannelId?: string | null;
}): Promise<CreatedInvite> {
  // PBA-L3c-002 (+ verifier V-002a): the scope must be a non-DM channel of THIS
  // workspace that the INVITER is seated in — an invite can never grant access the
  // inviter doesn't already have.
  if (args.scopeChannelId && !(await scopeChannelAllowed(args.workspaceId, args.scopeChannelId, args.invitedBySub))) {
    throw new Error("scope channel is not an invitable channel for this inviter");
  }
  const token = randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + INVITE_TTL_MS);
  const email = args.email.trim().toLowerCase();

  await db().insert(invites).values({
    tokenHash,
    workspaceId: args.workspaceId,
    email,
    role: args.role,
    scopeChannelId: args.scopeChannelId ?? null,
    invitedBySub: args.invitedBySub,
    expiresAt,
  });

  await appendAudit({ workspaceId: args.workspaceId, actorSub: args.invitedBySub, event: "member_invited", target: email });
  return { token, email, role: args.role, expiresAt: expiresAt.toISOString() };
}

type Db = Pick<ReturnType<typeof db>, "select">;

/**
 * May `inviterSub` scope an invite to `channelId`? Only a non-DM channel of this
 * workspace in which the inviter is currently seated (verifier V-002a: an Admin not in a
 * DM must not be able to mint an invite that seats anyone — themself or a sock-puppet —
 * into it).
 */
export async function scopeChannelAllowed(workspaceId: string, channelId: string, inviterSub: string, d: Db = db()): Promise<boolean> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(channelId)) return false;
  const [c] = await d
    .select({ kind: channels.kind, seat: channelMembers.sub })
    .from(channels)
    .innerJoin(channelMembers, and(eq(channelMembers.channelId, channels.id), eq(channelMembers.sub, inviterSub)))
    .where(and(eq(channels.workspaceId, workspaceId), eq(channels.id, channelId)))
    .limit(1);
  return Boolean(c) && c!.kind !== "dm";
}

/** Resolve a raw invite token to its (unexpired, unaccepted) details, or null. */
export async function lookupInvite(token: string): Promise<(PendingInvite & { tokenHash: string }) | null> {
  const tokenHash = hashToken(token);
  const [row] = await db()
    .select({
      tokenHash: invites.tokenHash,
      email: invites.email,
      role: invites.role,
      workspaceId: invites.workspaceId,
      invitedBySub: invites.invitedBySub,
      expiresAt: invites.expiresAt,
      scopeChannelId: invites.scopeChannelId,
      acceptedAt: invites.acceptedAt,
    })
    .from(invites)
    .where(eq(invites.tokenHash, tokenHash))
    .limit(1);
  if (!row || row.acceptedAt || row.expiresAt.getTime() < Date.now()) return null;

  // Resolve the workspace name for the join screen.
  const [ws] = await db().select({ name: workspaces.name }).from(workspaces).where(eq(workspaces.id, row.workspaceId)).limit(1);
  return {
    tokenHash: row.tokenHash,
    email: row.email,
    role: row.role as Role,
    workspaceId: row.workspaceId,
    workspaceName: ws?.name ?? "the workspace",
    invitedBySub: row.invitedBySub,
    expiresAt: row.expiresAt.toISOString(),
    scopeChannelId: row.scopeChannelId,
  };
}

export type AcceptResult =
  | { ok: true; workspaceId: string; alreadyMember: boolean }
  | { ok: false; reason: "invalid" };

/**
 * Accept an invite, binding the SIGNED-IN identity to the workspace at the granted
 * role. Frictionless + idempotent by design:
 *  - The invite link is a secret bearer credential (sent only to the invited email,
 *    single-use, 7-day expiry). Whoever opens it joins as whatever Citrate account
 *    they're signed into — we do NOT require the signed-in email to match the invite
 *    email. (An email-match check added friction without real security: the bearer
 *    link is the gate, and it forced people invited at one address but signed in with
 *    another — Google, wallet, passkey — to fail. Standard Slack/Linear invite model.)
 *  - Already an ACTIVE member → success (route them in); we never downgrade an
 *    existing role (e.g. an Owner accepting a Member invite stays Owner).
 *  - Previously offboarded/invited row → reactivated at the granted role.
 * Only an invalid/expired/used token fails, and a token is consumed exactly once even
 * under concurrent redemption (PBA-L3c-023).
 */
export async function acceptInvite(args: {
  token: string;
  sub: string;
  sessionEmail?: string | null; // already email_verified-gated upstream; for display/contact
  walletAddress?: string | null;
  displayName?: string | null;
  kycStatus?: string | null;
}): Promise<AcceptResult> {
  // PBA-L3c-023: claim the single-use invite ATOMICALLY first. The conditional UPDATE
  // (unaccepted AND unexpired) is the only gate: of N concurrent accepts of one token,
  // exactly one gets the row back; the rest see "invalid". Membership + channel seating
  // run in the same transaction, so a failure un-claims the invite.
  const tokenHash = hashToken(args.token);
  const result = await db().transaction(async (tx) => {
    const [invite] = await tx
      .update(invites)
      .set({ acceptedBySub: args.sub, acceptedAt: new Date() })
      .where(and(eq(invites.tokenHash, tokenHash), isNull(invites.acceptedAt), gt(invites.expiresAt, new Date())))
      .returning({ workspaceId: invites.workspaceId, email: invites.email, role: invites.role, scopeChannelId: invites.scopeChannelId, invitedBySub: invites.invitedBySub });
    if (!invite) return null;

    // Contact email for the member row = their real verified email if we have one,
    // else the address the invite was sent to (best-effort for display/contact).
    const memberEmail = args.sessionEmail?.toLowerCase() ?? invite.email;
    const [existing] = await tx
      .select({ status: members.status })
      .from(members)
      .where(and(eq(members.workspaceId, invite.workspaceId), eq(members.sub, args.sub)))
      .limit(1);

    let alreadyMember = false;
    if (existing && existing.status === "active") {
      // Idempotent: already in. Don't touch their role/status (no accidental downgrade).
      alreadyMember = true;
    } else if (existing) {
      // Reactivate a previously offboarded/invited row at the granted role.
      await tx
        .update(members)
        .set({ role: invite.role, status: "active", email: memberEmail, walletAddress: args.walletAddress ?? null })
        .where(and(eq(members.workspaceId, invite.workspaceId), eq(members.sub, args.sub)));
    } else {
      await tx.insert(members).values({
        workspaceId: invite.workspaceId,
        sub: args.sub,
        walletAddress: args.walletAddress ?? null,
        email: memberEmail,
        displayName: args.displayName ?? null,
        role: invite.role,
        status: "active",
        kycStatus: args.kycStatus ?? null,
      });
    }

    // PBA-L3c-002: honour the invite's channel scope — seat the NEW member in the scoped
    // channel (Partner/Guest see ONLY the channels they are seated in). Verifier V-002a:
    // an identity that was already an active member is never seated through an invite,
    // and the scope is re-checked at redemption (non-DM, inviter still seated), so an
    // invite can't be used to walk into a channel the inviter can't see.
    if (invite.scopeChannelId && !alreadyMember && (await scopeChannelAllowed(invite.workspaceId, invite.scopeChannelId, invite.invitedBySub, tx))) {
      await tx
        .insert(channelMembers)
        .values({ workspaceId: invite.workspaceId, channelId: invite.scopeChannelId, sub: args.sub })
        .onConflictDoNothing();
    }
    return { workspaceId: invite.workspaceId, alreadyMember, memberEmail };
  });

  if (!result) return { ok: false, reason: "invalid" };
  if (!result.alreadyMember) {
    await appendAudit({ workspaceId: result.workspaceId, actorSub: args.sub, event: "member_joined", target: result.memberEmail });
  }
  return { ok: true, workspaceId: result.workspaceId, alreadyMember: result.alreadyMember };
}

/** Pending (unaccepted, unexpired) invites for the members screen. */
export async function listPendingInvites(workspaceId: string): Promise<{ email: string; role: Role; expiresAt: string }[]> {
  const rows = await db()
    .select({ email: invites.email, role: invites.role, expiresAt: invites.expiresAt, acceptedAt: invites.acceptedAt })
    .from(invites)
    .where(and(eq(invites.workspaceId, workspaceId), isNull(invites.acceptedAt)))
    .orderBy(desc(invites.createdAt));
  const now = Date.now();
  return rows
    .filter((r) => r.expiresAt.getTime() > now)
    .map((r) => ({ email: r.email, role: r.role as Role, expiresAt: r.expiresAt.toISOString() }));
}
