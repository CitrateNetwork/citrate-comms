import { describe, expect, it } from "vitest";
import { parseChartSpec } from "./chart-spec";

describe("chart spec parsing (RR-2) — inline data only, no remote fetch", () => {
  it("accepts a valid inline Vega-Lite spec", () => {
    const r = parseChartSpec(JSON.stringify({ mark: "bar", data: { values: [{ a: "x", b: 1 }] }, encoding: {} }));
    expect(r.ok).toBe(true);
  });

  it("REJECTS a spec that fetches a remote url (anywhere, any depth)", () => {
    expect(parseChartSpec(JSON.stringify({ mark: "line", data: { url: "https://evil.example/data.json" } })).ok).toBe(false);
    expect(parseChartSpec(JSON.stringify({ layer: [{ data: { url: "http://x/y" } }] })).ok).toBe(false);
  });

  it("rejects invalid JSON and non-objects", () => {
    expect(parseChartSpec("{not json").ok).toBe(false);
    expect(parseChartSpec("[1,2,3]").ok).toBe(false);
    expect(parseChartSpec('"a string"').ok).toBe(false);
  });
});
