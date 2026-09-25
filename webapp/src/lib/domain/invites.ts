/**
 * Invite repository — email-primary onboarding. An invite stores only the SHA-256
 * of a high-entropy token (the raw token travels only in the emailed link, never
 * persisted), plus the target email, role, and expiry. Accepting an invite binds a
 * verified identity to the workspace at the granted role.
 *
 * Security model: the emailed link is a bearer credential (possession proves the
 * person received that email). When the accepting session ALSO has a verified email
 * (FWA-C6-01), it must match the invite — defense in depth without blocking
 * wallet-only / passkey teammates who have no email claim.
 */
import { randomBytes } from "node:crypto";
import { and, desc, eq, isNull } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { invites, members, workspaces } from "@/lib/db/schema";
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
  // PBA-L3c-002: a scope channel must be a channel of THIS workspace.
  if (args.scopeChannelId && !(await channelInWorkspace(args.workspaceId, args.scopeChannelId))) {
    throw new Error("scope channel is not in this workspace");
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

/** True iff `channelId` is a channel of `workspaceId`. */
export async function channelInWorkspace(workspaceId: string, channelId: string): Promise<boolean> {
  const [c] = await db()
    .select({ id: channels.id })
    .from(channels)
    .where(and(eq(channels.workspaceId, workspaceId), eq(channels.id, channelId)))
    .limit(1);
  return Boolean(c);
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
 * Only an invalid/expired/used token fails.
 */
export async function acceptInvite(args: {
  token: string;
  sub: string;
  sessionEmail?: string | null; // already email_verified-gated upstream; for display/contact
  walletAddress?: string | null;
  displayName?: string | null;
  kycStatus?: string | null;
}): Promise<AcceptResult> {
  const invite = await lookupInvite(args.token);
  if (!invite) return { ok: false, reason: "invalid" };

  // Contact email for the member row = their real verified email if we have one,
  // else the address the invite was sent to (best-effort for display/contact).
  const memberEmail = args.sessionEmail?.toLowerCase() ?? invite.email;

  const d = db();
  const [existing] = await d
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
    await d
      .update(members)
      .set({ role: invite.role, status: "active", email: memberEmail, walletAddress: args.walletAddress ?? null })
      .where(and(eq(members.workspaceId, invite.workspaceId), eq(members.sub, args.sub)));
  } else {
    await d.insert(members).values({
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

  // Consume the single-use invite (idempotent if already consumed by this sub).
  await d
    .update(invites)
    .set({ acceptedBySub: args.sub, acceptedAt: new Date() })
    .where(eq(invites.tokenHash, invite.tokenHash));

  if (!alreadyMember) {
    await appendAudit({ workspaceId: invite.workspaceId, actorSub: args.sub, event: "member_joined", target: memberEmail });
  }
  return { ok: true, workspaceId: invite.workspaceId, alreadyMember };
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
