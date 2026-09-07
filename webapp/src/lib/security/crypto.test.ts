/**
 * Unsubscribe-token round-trip + tamper resistance. The token authorizes a
 * one-click unsubscribe with no DB lookup, so its HMAC must be unforgeable and
 * email-bound. (Field-encryption round-trips are covered implicitly by the no-pii
 * discipline; this locks the compliance-critical path.)
 */
import { beforeAll, describe, expect, it } from "vitest";
import { auditMac, decryptField, encryptField, hashId, unsubscribeToken, verifyUnsubscribeToken } from "./crypto";

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

describe("decryptField GCM tag length (CM2-B-B017)", () => {
  it("round-trips a well-formed envelope", () => {
    expect(decryptField("ws1", encryptField("ws1", "secret"))).toBe("secret");
  });

  it("rejects a truncated (short) auth tag instead of returning plaintext", () => {
    const packed = encryptField("ws1", "top-secret");
    const [v, iv, tag, ct] = packed.split(":") as [string, string, string, string];
    const shortTag = Buffer.from(tag, "base64").subarray(0, 4).toString("base64");
    // Pre-fix Node accepted the 4-byte tag and returned "top-secret".
    expect(() => decryptField("ws1", `${v}:${iv}:${shortTag}:${ct}`)).toThrow();
  });
});

describe("hashId fail-closed (CIT-COMMS-008 / CM2-B-B024)", () => {
  it("produces a stable keyed hash when the key is set", () => {
    expect(hashId("1.2.3.4")).toBe(hashId("1.2.3.4"));
    expect(hashId("1.2.3.4")).not.toBe(hashId("5.6.7.8"));
  });

  it("throws (fail-closed) when COMMS_ENC_KEY is unset rather than using a public salt", () => {
    const saved = process.env.COMMS_ENC_KEY;
    delete process.env.COMMS_ENC_KEY;
    try {
      expect(() => hashId("1.2.3.4")).toThrow();
    } finally {
      process.env.COMMS_ENC_KEY = saved;
    }
  });
});

describe("auditMac keyed audit chain (CM2-B-B015)", () => {
  it("is deterministic per (workspace, message) and workspace-separated", () => {
    expect(auditMac("ws1", "m")).toBe(auditMac("ws1", "m"));
    expect(auditMac("ws1", "m")).not.toBe(auditMac("ws2", "m"));
    expect(auditMac("ws1", "m")).not.toBe(auditMac("ws1", "m2"));
  });

  it("is KEYED — a different master key yields a different MAC (insider cannot recompute without the key)", () => {
    const saved = process.env.COMMS_ENC_KEY;
    const withKeyA = auditMac("ws1", "record");
    process.env.COMMS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
    try {
      expect(auditMac("ws1", "record")).not.toBe(withKeyA);
    } finally {
      process.env.COMMS_ENC_KEY = saved;
    }
  });

  it("fails closed when COMMS_ENC_KEY is unset", () => {
    const saved = process.env.COMMS_ENC_KEY;
    delete process.env.COMMS_ENC_KEY;
    try {
      expect(() => auditMac("ws1", "m")).toThrow();
    } finally {
      process.env.COMMS_ENC_KEY = saved;
    }
  });
});
