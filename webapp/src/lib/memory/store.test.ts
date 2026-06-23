import { describe, expect, it } from "vitest";
import { TRUST_ORDER, trustRank, meetsTrustFloor, crmRepo } from "./store";

describe("trust tiers", () => {
  it("orders strongest → weakest", () => {
    expect(TRUST_ORDER[0]).toBe("derived-deterministic");
    expect(TRUST_ORDER[TRUST_ORDER.length - 1]).toBe("inferred-advisory");
    expect(trustRank("human-confirmed")).toBeLessThan(trustRank("agent-asserted"));
  });

  it("meetsTrustFloor admits items at least as trusted as the floor", () => {
    expect(meetsTrustFloor("human-confirmed", "agent-asserted")).toBe(true); // stronger passes
    expect(meetsTrustFloor("inferred-advisory", "human-confirmed")).toBe(false); // weaker fails
    expect(meetsTrustFloor("agent-asserted")).toBe(true); // no floor ⇒ all pass
    expect(meetsTrustFloor("agent-asserted", "agent-asserted")).toBe(true); // equal passes
  });

  it("crmRepo namespaces by workspace", () => {
    expect(crmRepo("ws-123")).toBe("crm:ws-123");
  });
});
