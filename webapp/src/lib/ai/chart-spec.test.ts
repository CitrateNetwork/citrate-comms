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

  // PBA-L3c-021: url/href channels given as encoding OBJECTS are rejected too, not only
  // string-valued url keys.
  it("REJECTS an image mark whose url channel is an encoding object", () => {
    const spec = { data: { values: [{ u: "https://external.example/image.png?q=1" }] }, mark: "image", encoding: { url: { field: "u" }, x: { value: 0 }, y: { value: 0 } } };
    expect(parseChartSpec(JSON.stringify(spec)).ok).toBe(false);
  });

  it("REJECTS an href channel (link-out on click) and href mark properties", () => {
    expect(parseChartSpec(JSON.stringify({ data: { values: [{ h: "https://external.example/link" }] }, mark: "point", encoding: { href: { field: "h" } } })).ok).toBe(false);
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

describe("chart spec — remote-reach inspection boundaries (PBA-L3c-021 mutation hardening)", () => {
  const nest = (k: number) => {
    let x: Record<string, unknown> = {};
    for (let i = 0; i < k; i++) x = { a: x };
    return { data: { values: [] }, mark: "bar", ...x };
  };
  it("fails closed exactly past the inspection depth, even with no url anywhere", () => {
    expect(parseChartSpec(JSON.stringify(nest(15))).ok).toBe(true);
    expect(parseChartSpec(JSON.stringify(nest(16))).ok).toBe(true);
    expect(parseChartSpec(JSON.stringify(nest(17))).ok).toBe(false);
    let arr: unknown = [];
    for (let i = 0; i < 20; i++) arr = [arr];
    expect(parseChartSpec(JSON.stringify({ data: { values: arr } })).ok).toBe(false);
  });
  it("a remote key in ONE array element is enough; null values are fine", () => {
    expect(parseChartSpec(JSON.stringify({ layer: [{ mark: "bar" }, { data: { url: "https://x/y" } }] })).ok).toBe(false);
    expect(parseChartSpec(JSON.stringify({ data: { values: [{ a: null, b: 1 }] }, mark: "bar" })).ok).toBe(true);
  });
  it("image marks and loader keys are refused; the WORD image elsewhere is not", () => {
    expect(parseChartSpec(JSON.stringify({ data: { values: [] }, mark: "image" })).ok).toBe(false);
    expect(parseChartSpec(JSON.stringify({ data: { values: [] }, mark: "IMAGE" })).ok).toBe(false);
    expect(parseChartSpec(JSON.stringify({ data: { values: [] }, mark: "bar", loader: {} })).ok).toBe(false);
    expect(parseChartSpec(JSON.stringify({ data: { values: [{ kind: "image" }] }, title: "image", mark: "bar" })).ok).toBe(true);
    expect(parseChartSpec(JSON.stringify({ data: { values: [] }, mark: { type: "bar", tooltip: true } })).ok).toBe(true);
  });
});
