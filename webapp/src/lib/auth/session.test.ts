/**
 * Auth fail-closed tests (ported from citrate-dataroom). The WEB-1 posture: an
 * unset/unknown auth mode must resolve to `oidc` (reject everything), and `mock`
 * in production is disabled unless ALLOW_MOCK_AUTH=1.
 */
import { describe, expect, it } from "vitest";
import { resolveServerAuthMode } from "./session";

describe("resolveServerAuthMode (WEB-1 fail-closed)", () => {
  it("defaults to oidc when unset", () => {
    expect(resolveServerAuthMode({})).toBe("oidc");
  });
  it("defaults to oidc on an unknown value", () => {
    expect(resolveServerAuthMode({ NEXT_PUBLIC_AUTH_MODE: "lol" })).toBe("oidc");
  });
  it("honors explicit oidc", () => {
    expect(resolveServerAuthMode({ NEXT_PUBLIC_AUTH_MODE: "oidc" })).toBe("oidc");
  });
  it("allows mock in dev", () => {
    expect(resolveServerAuthMode({ NEXT_PUBLIC_AUTH_MODE: "mock", NODE_ENV: "development" })).toBe("mock");
  });
  it("disables mock in production unless ALLOW_MOCK_AUTH=1", () => {
    expect(resolveServerAuthMode({ NEXT_PUBLIC_AUTH_MODE: "mock", NODE_ENV: "production" })).toBe("mock-disabled");
    expect(
      resolveServerAuthMode({ NEXT_PUBLIC_AUTH_MODE: "mock", NODE_ENV: "production", ALLOW_MOCK_AUTH: "1" }),
    ).toBe("mock");
  });
});
