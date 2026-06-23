import { describe, expect, it } from "vitest";
import { summarizeActivity } from "./crm-activity";

// A stand-in for sensitive record data that must NEVER appear in an activity summary.
const SECRET = "Jane Doe jane@acme.com $1,250,000";

describe("activity summaries are value-free", () => {
  it("builds summaries only from controlled tokens", () => {
    expect(summarizeActivity("account", { kind: "created" })).toBe("Account created");
    expect(summarizeActivity("deal", { kind: "stage_changed", from: "Lead", to: "Qualified" })).toBe("Stage Lead→Qualified");
    expect(summarizeActivity("deal", { kind: "field_changed", fieldLabel: "Probability (%)" })).toBe("Field “Probability (%)” updated");
    expect(summarizeActivity("account", { kind: "note_added", noteType: "meeting" })).toBe("Meeting added");
    expect(summarizeActivity("deal", { kind: "document_added" })).toBe("Document added");
    expect(summarizeActivity("account", { kind: "tagged", tag: "VIP" })).toBe("Tagged “VIP”");
    expect(summarizeActivity("deal", { kind: "agent_action", tool: "crm.read" })).toBe("Agent ran crm.read");
  });

  it("never echoes a raw record value (only stages/labels/types flow in by construction)", () => {
    // The discriminated input has no slot for a raw value — these are the only inputs.
    const all = [
      summarizeActivity("account", { kind: "created" }),
      summarizeActivity("deal", { kind: "stage_changed", from: "Proposal", to: "Won" }),
      summarizeActivity("contact", { kind: "note_added", noteType: "call" }),
      summarizeActivity("account", { kind: "contact_linked" }),
    ].join(" | ");
    expect(all).not.toContain(SECRET);
    expect(all).not.toContain("@");
    expect(all).not.toContain("$");
  });
});
