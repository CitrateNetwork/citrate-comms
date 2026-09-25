/**
 * RBAC parity tests — mirror the Rust tests in
 * `citrate-comms/crates/comms-core/src/rbac.rs` (`capability_matrix`,
 * `anti_escalation_on_grant`). If the native matrix changes, update both in
 * lockstep so the web tier and the relay agree on policy (the bridge depends on it).
 */
import { describe, expect, it } from "vitest";
import { Capability, ROLES, can, canGrant, isAdminRole, isInternalRole, type Role } from "./matrix";

describe("capability_matrix (parity with rbac.rs)", () => {
  it("matches the Rust matrix exactly", () => {
    expect(can("Owner", Capability.ManageWorkspace)).toBe(true);
    expect(can("Admin", Capability.RemoveMember)).toBe(true);
    expect(can("Member", Capability.RemoveMember)).toBe(false);
    expect(can("Member", Capability.PostMessage)).toBe(true);
    expect(can("Partner", Capability.ReadChannel)).toBe(true);
    expect(can("Partner", Capability.CreateChannel)).toBe(false);
    expect(can("Guest", Capability.ReadChannel)).toBe(true);
    expect(can("Guest", Capability.PostMessage)).toBe(false);
  });

  it("DMs/group DMs: Members + Partners may create, full channels stay Owner/Admin", () => {
    // CreateDirectMessage — Members + Partners can start DMs (web-tier divergence).
    expect(can("Owner", Capability.CreateDirectMessage)).toBe(true);
    expect(can("Admin", Capability.CreateDirectMessage)).toBe(true);
    expect(can("Member", Capability.CreateDirectMessage)).toBe(true);
    expect(can("Partner", Capability.CreateDirectMessage)).toBe(true);
    // Guests and Agents cannot initiate conversations.
    expect(can("Guest", Capability.CreateDirectMessage)).toBe(false);
    expect(can("Agent", Capability.CreateDirectMessage)).toBe(false);
    // Full channel/forum creation stays Owner/Admin-only.
    expect(can("Member", Capability.CreateChannel)).toBe(false);
    expect(can("Partner", Capability.CreateChannel)).toBe(false);
  });

  it("delete cards: Owner/Admin only; Members edit but never delete", () => {
    expect(can("Owner", Capability.DeleteRecord)).toBe(true);
    expect(can("Admin", Capability.DeleteRecord)).toBe(true);
    expect(can("Member", Capability.DeleteRecord)).toBe(false);
    expect(can("Partner", Capability.DeleteRecord)).toBe(false);
    expect(can("Guest", Capability.DeleteRecord)).toBe(false);
    expect(can("Agent", Capability.DeleteRecord)).toBe(false);
    // Members can still create + edit (CreateRecord).
    expect(can("Member", Capability.CreateRecord)).toBe(true);
  });

  it("enforces the agent guardrail: read + post, never membership mutation", () => {
    expect(can("Agent", Capability.PostMessage)).toBe(true);
    expect(can("Agent", Capability.ReadChannel)).toBe(true);
    expect(can("Agent", Capability.AddMember)).toBe(false);
    expect(can("Agent", Capability.RemoveMember)).toBe(false);
    expect(can("Agent", Capability.AssignRole)).toBe(false);
    expect(can("Agent", Capability.CreateChannel)).toBe(false);
    expect(can("Agent", Capability.CreateDirectMessage)).toBe(false);
  });

  it("Owner holds every capability", () => {
    for (const cap of Object.values(Capability)) {
      expect(can("Owner", cap as Capability)).toBe(true);
    }
  });
});

describe("anti_escalation_on_grant (parity with rbac.rs)", () => {
  it("matches the Rust grant rules", () => {
    expect(canGrant("Owner", "Admin")).toBe(true);
    expect(canGrant("Admin", "Member")).toBe(true);
    expect(canGrant("Admin", "Admin")).toBe(false); // admin can't mint admins
    expect(canGrant("Admin", "Owner")).toBe(false);
    expect(canGrant("Member", "Member")).toBe(false);
  });

  it("only Owner/Admin can grant anything", () => {
    const granters: Role[] = ["Owner", "Admin"];
    for (const r of ROLES) {
      const grantsAnything = ROLES.some((t) => canGrant(r, t));
      expect(grantsAnything).toBe(granters.includes(r));
    }
  });
});

describe("PBA-L3c-002/007 web-tier role predicates", () => {
  it("ReadWorkspace / isInternalRole: internal roles only", () => {
    expect(ROLES.filter((r) => isInternalRole(r))).toEqual(["Owner", "Admin", "Member", "Agent"]);
    expect(ROLES.filter((r) => can(r, Capability.ReadWorkspace))).toEqual(["Owner", "Admin", "Member", "Agent"]);
  });
  it("isAdminRole: Owner and Admin only", () => {
    expect(ROLES.filter((r) => isAdminRole(r))).toEqual(["Owner", "Admin"]);
  });
  it("Agent holds exactly read, workspace-read and post", () => {
    expect(Object.values(Capability).filter((c) => can("Agent", c as Capability)).sort()).toEqual(["PostMessage", "ReadChannel", "ReadWorkspace"]);
  });
  it("an unknown role holds nothing (fail closed)", () => {
    expect(can("Nobody" as Role, Capability.ReadChannel)).toBe(false);
  });
});
