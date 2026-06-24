import { describe, it, expect } from "vitest";
import { parseMentions, type Mentionable } from "@/lib/mentions";

/**
 * MEN-2 unit coverage focuses on the pure mention→recipient resolution that drives
 * notifyChannelMentions (DB insertion is integration-tested manually). The rule: only
 * human members are pinged, the actor never pings themselves, and dupes collapse.
 */
const MEMBERS: Mentionable[] = [
  { id: "s1", name: "Saul Loveman", sub: "s1", kind: "member" },
  { id: "s2", name: "Ada Lovelace", sub: "s2", kind: "member" },
  { id: "a1", name: "CRM Agent", sub: "agent:crm", kind: "agent" },
];

function recipientsOf(body: string, actorSub: string): string[] {
  const { members } = parseMentions(body, MEMBERS);
  return members.map((m) => m.sub).filter((s) => s !== actorSub);
}

describe("MEN-2 — mention → recipients", () => {
  it("pings mentioned human members, not the actor", () => {
    expect(recipientsOf("hey @saul-loveman and @ada-lovelace look here", "s1")).toEqual(["s2"]);
  });
  it("ignores agent mentions (those drive MEN-1 replies, not pings)", () => {
    const { members, agents } = parseMentions("@crm-agent please summarize for @ada-lovelace", MEMBERS);
    expect(members.map((m) => m.sub)).toEqual(["s2"]);
    expect(agents.map((a) => a.sub)).toEqual(["agent:crm"]);
  });
  it("no mentions → no recipients", () => {
    expect(recipientsOf("just a normal message", "s1")).toEqual([]);
  });
});
