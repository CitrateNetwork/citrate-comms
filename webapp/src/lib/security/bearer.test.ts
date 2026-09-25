import { describe, it, expect } from "vitest";
import { bearerMatches } from "./bearer";

describe("bearerMatches — constant-time machine-route auth (PBA-L3c-035)", () => {
  it("accepts exactly the configured secret with the Bearer scheme", () => {
    expect(bearerMatches("Bearer s3cret", "s3cret")).toBe(true);
    expect(bearerMatches("bearer s3cret", "s3cret")).toBe(true);
  });
  it("refuses wrong, prefix, suffix, schemeless, empty and unset", () => {
    expect(bearerMatches("Bearer s3cre", "s3cret")).toBe(false);
    expect(bearerMatches("Bearer s3cretX", "s3cret")).toBe(false);
    expect(bearerMatches("s3cret", "s3cret")).toBe(false);
    expect(bearerMatches(null, "s3cret")).toBe(false);
    expect(bearerMatches("Bearer ", "")).toBe(false);
    expect(bearerMatches("Bearer x", undefined)).toBe(false);
  });
});
