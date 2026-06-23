/**
 * RBAC — roles → capabilities, ported 1:1 from the native authority
 * `citrate-comms/crates/comms-core/src/rbac.rs` (`can`, `can_grant`).
 *
 * The web tier enforces this matrix server-side on EVERY mutation (the client only
 * hides affordances; it never decides authorization). Keeping this a verbatim port
 * of the Rust matrix means the web tier and the native relay agree on policy, which
 * the bridge depends on. The parity tests in matrix.test.ts mirror the Rust tests
 * (`capability_matrix`, `anti_escalation_on_grant`) — if the Rust matrix changes,
 * those tests must be updated in lockstep.
 *
 * The agent guardrail is load-bearing: Role.Agent may read + post, but NEVER mutate
 * membership or assign roles.
 *
 * WEB DIVERGENCE (2026-06-23): `CreateDirectMessage` is a web-tier addition NOT yet in
 * `rbac.rs`. It lets Members + Partners start DMs / group DMs (kind=dm channels) while
 * keeping full channel/forum creation (`CreateChannel`) Owner/Admin-only. When DMs flow
 * over the bridge, add the same capability to the native matrix to keep policy in sync.
 */

export type Role = "Owner" | "Admin" | "Member" | "Partner" | "Guest" | "Agent";

export const ROLES: readonly Role[] = ["Owner", "Admin", "Member", "Partner", "Guest", "Agent"];

/** A discrete permission. Mirrors `rbac::Capability`. */
export enum Capability {
  ReadChannel = "ReadChannel",
  PostMessage = "PostMessage",
  CreateThread = "CreateThread",
  CreateChannel = "CreateChannel",
  CreateDirectMessage = "CreateDirectMessage", // DMs + group DMs (web-tier; see header note)
  AddMember = "AddMember",
  RemoveMember = "RemoveMember",
  AddAgent = "AddAgent",
  RemoveAgent = "RemoveAgent",
  AssignRole = "AssignRole",
  ManageWorkspace = "ManageWorkspace",
  CreateRecord = "CreateRecord", // CRM / PM entities
}

const ADMIN_CAPS = new Set<Capability>([
  Capability.ReadChannel,
  Capability.PostMessage,
  Capability.CreateThread,
  Capability.CreateChannel,
  Capability.CreateDirectMessage,
  Capability.AddMember,
  Capability.RemoveMember,
  Capability.AddAgent,
  Capability.RemoveAgent,
  Capability.AssignRole,
  Capability.CreateRecord,
]);

const MEMBER_CAPS = new Set<Capability>([
  Capability.ReadChannel,
  Capability.PostMessage,
  Capability.CreateThread,
  Capability.CreateDirectMessage,
  Capability.CreateRecord,
]);

// Partner: scoped read/post PLUS the ability to start a DM / group DM with people in
// the workspace (kind=dm only — never a full channel/forum).
const PARTNER_CAPS = new Set<Capability>([
  Capability.ReadChannel,
  Capability.PostMessage,
  Capability.CreateDirectMessage,
]);

const READ_POST = new Set<Capability>([Capability.ReadChannel, Capability.PostMessage]);

/** Does `role` hold `cap`? The authoritative capability matrix (PLANSET/02 §4). */
export function can(role: Role, cap: Capability): boolean {
  switch (role) {
    case "Owner":
      return true; // everything
    case "Admin":
      return ADMIN_CAPS.has(cap);
    case "Member":
      return MEMBER_CAPS.has(cap);
    // Partner: scoped read/post + start DMs/group DMs (channel scope enforced separately).
    case "Partner":
      return PARTNER_CAPS.has(cap);
    case "Guest":
      return cap === Capability.ReadChannel;
    // Agent: read + post in channels it is a member of; NO membership-mutating caps,
    // and agents do not INITIATE conversations (no DM creation).
    case "Agent":
      return READ_POST.has(cap);
    default:
      return false;
  }
}

/**
 * May an issuer holding `issuerRole` grant `targetRole`? Prevents privilege
 * escalation: an Admin cannot mint Owners or other Admins.
 */
export function canGrant(issuerRole: Role, targetRole: Role): boolean {
  switch (issuerRole) {
    case "Owner":
      return true;
    case "Admin":
      return targetRole === "Member" || targetRole === "Partner" || targetRole === "Guest" || targetRole === "Agent";
    default:
      return false;
  }
}

/** A one-line capability summary for tooltips/role chips (UI affordance only). */
export const ROLE_SUMMARY: Record<Role, string> = {
  Owner: "Full control — manages the workspace and assigns admins.",
  Admin: "Onboards/offboards members & agents, creates channels, assigns roles.",
  Member: "Posts, creates threads & DMs, owns CRM/PM records.",
  Partner: "External — scoped read/post in shared channels; can start DMs.",
  Guest: "Read-only, expiring access.",
  Agent: "AI participant — reads & posts; cannot change membership.",
};
