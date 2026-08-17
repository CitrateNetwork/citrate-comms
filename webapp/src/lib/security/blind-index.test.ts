import { beforeAll, describe, it, expect } from "vitest";
import { blindIndex } from "./crypto";

beforeAll(() => {
  process.env.COMMS_ENC_KEY = Buffer.alloc(32, 3).toString("base64");
});

const WS = "22222222-2222-2222-2222-222222222222";

describe("blindIndex", () => {
  it("is deterministic for equal inputs (enables dedupe)", () => {
    expect(blindIndex(WS, "email", "jane@acme.com")).toBe(blindIndex(WS, "email", "jane@acme.com"));
  });
  it("is domain-separated", () => {
    expect(blindIndex(WS, "email", "x")).not.toBe(blindIndex(WS, "phone", "x"));
  });
  it("is workspace-separated (no cross-tenant collisions)", () => {
    const other = "33333333-3333-3333-3333-333333333333";
    expect(blindIndex(WS, "email", "x")).not.toBe(blindIndex(other, "email", "x"));
  });
  it("does not reveal the plaintext", () => {
    expect(blindIndex(WS, "email", "secret@acme.com")).not.toContain("secret");
  });
});
