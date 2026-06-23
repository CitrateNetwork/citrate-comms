/**
 * Unsubscribe-token round-trip + tamper resistance. The token authorizes a
 * one-click unsubscribe with no DB lookup, so its HMAC must be unforgeable and
 * email-bound. (Field-encryption round-trips are covered implicitly by the no-pii
 * discipline; this locks the compliance-critical path.)
 */
import { beforeAll, describe, expect, it } from "vitest";
import { unsubscribeToken, verifyUnsubscribeToken } from "./crypto";

beforeAll(() => {
  // Deterministic 32-byte key for the test (NOT a real secret).
  process.env.COMMS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
});

describe("unsubscribe token", () => {
  it("round-trips the email (case-normalized)", () => {
    const t = unsubscribeToken("Larry@Citrate.AI");
    expect(verifyUnsubscribeToken(t)).toBe("larry@citrate.ai");
  });

  it("rejects a tampered MAC", () => {
    const t = unsubscribeToken("a@b.com");
    const [e] = t.split(".");
    expect(verifyUnsubscribeToken(`${e}.AAAAAAAA`)).toBeNull();
  });

  it("rejects a swapped email (MAC no longer matches)", () => {
    const t = unsubscribeToken("victim@b.com");
    const mac = t.split(".")[1];
    const forgedEmail = Buffer.from("attacker@b.com", "utf8").toString("base64url");
    expect(verifyUnsubscribeToken(`${forgedEmail}.${mac}`)).toBeNull();
  });

  it("rejects malformed tokens", () => {
    expect(verifyUnsubscribeToken("")).toBeNull();
    expect(verifyUnsubscribeToken("nodot")).toBeNull();
  });
});
