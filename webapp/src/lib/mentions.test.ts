import { describe, it, expect } from "vitest";
import { toHandle, extractHandles, parseMentions, filterMentionables, type Mentionable } from "./mentions";

const CANDS: Mentionable[] = [
  { id: "p1", name: "Executive Assistant", sub: "agent:ea", kind: "agent" },
  { id: "p2", name: "CRM Agent", sub: "agent:crm", kind: "agent" },
  { id: "m1", name: "Saul Loveman", sub: "sub-saul", kind: "member" },
  { id: "m2", name: "Ada", sub: "sub-ada", kind: "member" },
];

describe("MEN — handles", () => {
  it("normalizes names to space-free handles", () => {
    expect(toHandle("Executive Assistant")).toBe("executive-assistant");
    expect(toHandle("CRM Agent")).toBe("crm-agent");
    expect(toHandle("  Weird!! Name  ")).toBe("weird-name");
  });
});

describe("MEN — extractHandles", () => {
  it("pulls distinct @handles, ignores emails", () => {
    expect(extractHandles("hi @ada and @crm-agent")).toEqual(["ada", "crm-agent"]);
    expect(extractHandles("mail me at foo@bar.com")).toEqual([]); // preceded by alnum → not a mention
    expect(extractHandles("@ada @ada")).toEqual(["ada"]);
  });
});

describe("MEN — parseMentions", () => {
  it("resolves agents and members separately", () => {
    const r = parseMentions("hey @executive-assistant can you and @ada look at this", CANDS);
    expect(r.agents.map((a) => a.id)).toEqual(["p1"]);
    expect(r.members.map((m) => m.id)).toEqual(["m2"]);
    expect(r.all).toHaveLength(2);
  });
  it("dedupes and ignores unknown handles", () => {
    const r = parseMentions("@crm-agent @crm-agent @nobody", CANDS);
    expect(r.all.map((c) => c.id)).toEqual(["p2"]);
  });
  it("matches a known handle that is a prefix of the typed token", () => {
    const r = parseMentions("@ada,", CANDS); // trailing punctuation stripped by extract
    expect(r.members.map((m) => m.id)).toEqual(["m2"]);
  });
});

describe("MEN — filterMentionables", () => {
  it("empty query returns all (agents first)", () => {
    const r = filterMentionables(CANDS, "");
    expect(r[0]!.kind).toBe("agent");
    expect(r).toHaveLength(4);
  });
  it("ranks prefix matches above substring", () => {
    const r = filterMentionables(CANDS, "a");
    // "ada" (handle prefix 'a') should rank above "executive-assistant"/"crm-agent" substrings
    expect(r[0]!.name).toBe("Ada");
  });
  it("matches by display name too", () => {
    const r = filterMentionables(CANDS, "saul");
    expect(r.map((c) => c.id)).toEqual(["m1"]);
  });
});
