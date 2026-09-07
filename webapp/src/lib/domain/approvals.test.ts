/**
 * CM2-B-B004 / CIT-COMMS-002 — the approval queue must not be a lower-privileged path
 * to a privileged op: an approver must hold the capability the action's DIRECT route
 * requires, and may not self-approve a high-risk action (separation of duties).
 *
 * CM2-B-B005 — the approver consents to what actually executes: a high-risk sandbox
 * payload is rendered in full, never truncated to a 140-char preview.
 */
import { describe, it, expect } from "vitest";
import { approvalAuthzError, describeAction, type AgentAction } from "./approvals";

const terminal: AgentAction = { kind: "runner.terminal", cmd: "curl http://169.254.169.254/latest/meta-data/" };
const del: AgentAction = { kind: "crm.delete", entity: "account", recordId: "11111111-2222-3333-4444-555555555555" };
const note: AgentAction = { kind: "crm.note", entity: "account", recordId: "r1", type: "note", body: "hi" };

describe("approval authorization (CM2-B-B004)", () => {
  it("a Member may NOT approve arbitrary sandbox execution or a CRM delete", () => {
    expect(approvalAuthzError("Member", terminal, "approver", "proposer")).toBe("forbidden");
    expect(approvalAuthzError("Member", del, "approver", "proposer")).toBe("forbidden"); // crm.delete = Owner/Admin only
  });

  it("arbitrary sandbox exec is Owner-only (ManageWorkspace); an Admin is not enough", () => {
    expect(approvalAuthzError("Owner", terminal, "owner", "proposer")).toBeNull();
    expect(approvalAuthzError("Admin", terminal, "admin", "proposer")).toBe("forbidden");
  });

  it("an Admin may approve a CRM delete (DeleteRecord) they did not propose", () => {
    expect(approvalAuthzError("Admin", del, "admin", "proposer")).toBeNull();
  });

  it("forbids self-approval of a high-risk action even for an Owner (separation of duties)", () => {
    expect(approvalAuthzError("Owner", terminal, "same-sub", "same-sub")).toBe("self_approval_forbidden");
  });

  it("still lets a Member approve an ordinary low-risk write", () => {
    expect(approvalAuthzError("Member", note, "approver", "proposer")).toBeNull();
  });
});

describe("approval consent surface (CM2-B-B005)", () => {
  it("renders a high-risk sandbox payload IN FULL, not a 140-char preview", () => {
    const marker = "__EXFIL_MARKER__";
    const source = "# benign roll-up\n" + "x".repeat(5000) + marker;
    const codeAction: AgentAction = { kind: "runner.code", lang: "python", source };
    const summary = describeAction(codeAction);
    expect(summary).toContain(marker); // the tail that a 140-char truncation would hide
    expect(summary).toContain(String(Buffer.byteLength(source))); // byte count shown
    expect(summary).not.toContain("…"); // no truncation ellipsis on the executable content
  });
});
