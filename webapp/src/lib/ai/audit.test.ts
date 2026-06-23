import { describe, expect, it } from "vitest";
import { __test } from "./audit";

const { redact, redactedArgs, hashArgs } = __test;

describe("tool-call audit redaction (no secrets in the transparency log)", () => {
  it("scrubs secret-looking keys at any depth", () => {
    const out = redact({
      query: "find Acme",
      apiKey: "cgk_live_should_never_appear",
      nested: { authorization: "Bearer abc", token: "t0ken", ok: "visible" },
      list: [{ password: "hunter2", note: "keep" }],
    }) as Record<string, unknown>;
    const json = JSON.stringify(out);
    expect(json).not.toContain("cgk_live_should_never_appear");
    expect(json).not.toContain("Bearer abc");
    expect(json).not.toContain("hunter2");
    expect(json).toContain("[redacted]");
    expect(json).toContain("visible"); // non-secret values preserved
    expect(json).toContain("keep");
  });

  it("truncates the serialized args and stays within the cap", () => {
    const big = { query: "x".repeat(10_000) };
    const s = redactedArgs(big);
    expect(s.length).toBeLessThanOrEqual(2000);
  });

  it("hashArgs is deterministic and order-sensitive on content", () => {
    expect(hashArgs({ a: 1, b: 2 })).toBe(hashArgs({ a: 1, b: 2 }));
    expect(hashArgs({ a: 1 })).not.toBe(hashArgs({ a: 2 }));
    expect(hashArgs({}).length).toBe(64); // blake3 hex
  });

  it("caps array length and recursion depth without throwing", () => {
    const deep: Record<string, unknown> = {};
    let cur = deep;
    for (let i = 0; i < 20; i++) {
      cur.next = {};
      cur = cur.next as Record<string, unknown>;
    }
    expect(() => redact({ big: Array.from({ length: 1000 }, (_, i) => i), deep })).not.toThrow();
    const out = redact({ arr: Array.from({ length: 1000 }, (_, i) => i) }) as { arr: unknown[] };
    expect(out.arr.length).toBeLessThanOrEqual(50);
  });
});
