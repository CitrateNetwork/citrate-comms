import { describe, it, expect } from "vitest";
import {
  structuredFromJson,
  normalizeRecords,
  extractEntities,
  recordToCells,
  extractionMapping,
  type ExtractedRecord,
} from "./import-extract";
import { heldByConfidence } from "./import-engine";

describe("structuredFromJson — deterministic JSON path", () => {
  it("maps a record array by known keys at confidence 1.0", () => {
    const recs = structuredFromJson(JSON.stringify([{ Company: "Acme", Website: "acme.com", Name: "Jane Roe", Email: "jane@acme.com", Role: "CEO", Budget: "$50k" }]));
    expect(recs).not.toBeNull();
    expect(recs!).toHaveLength(1);
    const r = recs![0]!;
    expect(r.account?.name).toBe("Acme");
    expect(r.account?.domain).toBe("acme.com");
    expect(r.contact?.name).toBe("Jane Roe");
    expect(r.contact?.email).toBe("jane@acme.com");
    expect(r.contact?.title).toBe("CEO");
    expect(r.deal?.value).toBe("$50k");
    expect(r.confidence).toBe(1);
  });

  it("accepts a bare object and a {records:[...]} envelope", () => {
    expect(structuredFromJson(JSON.stringify({ company: "A" }))).toHaveLength(1);
    expect(structuredFromJson(JSON.stringify({ records: [{ company: "A" }, { company: "B" }] }))).toHaveLength(2);
  });

  it("returns null for non-JSON prose", () => {
    expect(structuredFromJson("Just some meeting notes about Acme.")).toBeNull();
  });
});

describe("normalizeRecords — clamp/trim/drop", () => {
  it("clamps confidence to [0,1] and trims strings", () => {
    const [r] = normalizeRecords([{ contact: { name: "  Jane  " }, confidence: 4 }]);
    expect(r!.contact?.name).toBe("Jane");
    expect(r!.confidence).toBe(1);
  });

  it("drops records with no usable fields", () => {
    expect(normalizeRecords([{ confidence: 0.9 }, { note: "", confidence: 0.9 }])).toHaveLength(0);
  });

  it("defaults a missing/NaN confidence to 0 (→ held under any threshold)", () => {
    const [r] = normalizeRecords([{ account: { name: "Acme" } }]);
    expect(r!.confidence).toBe(0);
  });
});

describe("extractEntities — routing + fail-closed (G1)", () => {
  it("uses the JSON path without calling the model", async () => {
    let called = false;
    const res = await extractEntities(JSON.stringify([{ company: "Acme" }]), {
      doExtract: async () => { called = true; return { records: [] }; },
    });
    expect(res.source).toBe("json");
    expect(res.records).toHaveLength(1);
    expect(called).toBe(false);
  });

  it("calls the injected model for prose and normalizes its output", async () => {
    const res = await extractEntities("Met with Acme's CEO Jane Roe about a $50k deal.", {
      doExtract: async () => ({ records: [{ account: { name: "Acme" }, contact: { name: "Jane Roe", title: "CEO" }, deal: { value: "$50k" }, confidence: 0.92 }] }),
    });
    expect(res.source).toBe("model");
    expect(res.records[0]!.contact?.name).toBe("Jane Roe");
    expect(res.records[0]!.confidence).toBeCloseTo(0.92);
  });

  it("FAILS CLOSED: a throwing model yields zero records + an error, never a guess", async () => {
    const res = await extractEntities("some prose", {
      doExtract: async () => { throw new Error("gateway 503"); },
    });
    expect(res.records).toHaveLength(0);
    expect(res.error).toContain("503");
  });

  it("FAILS CLOSED: malformed model output is dropped, not written", async () => {
    const res = await extractEntities("prose", {
      // garbage records with no usable fields
      doExtract: async () => ({ records: [{ nonsense: true, confidence: 0.99 } as unknown] }),
    });
    expect(res.records).toHaveLength(0);
  });
});

describe("recordToCells / extractionMapping — identity staging", () => {
  it("flattens a record to canonical CRM-slot columns", () => {
    const r: ExtractedRecord = { account: { name: "Acme", domain: "acme.com" }, contact: { name: "Jane", email: "j@acme.com" }, note: "hot lead", confidence: 0.9 };
    const cells = recordToCells(r);
    expect(cells["account.name"]).toBe("Acme");
    expect(cells["contact.email"]).toBe("j@acme.com");
    expect(cells["note"]).toBe("hot lead");
    expect(cells["deal.value"]).toBeUndefined();
  });

  it("maps std columns to identical std targets and note to a custom field", () => {
    const spec = extractionMapping();
    const email = spec.columns.find((c) => c.column === "contact.email");
    expect(email!.map).toEqual({ kind: "std", target: "contact.email" });
    const note = spec.columns.find((c) => c.column === "note");
    expect(note!.map).toMatchObject({ kind: "custom", entity: "contact", key: "note" });
    expect(spec.dedupe).toEqual({ account: "domain", contact: "email" });
  });
});

describe("heldByConfidence — the confidence gate (G2)", () => {
  it("holds a model row below the threshold", () => {
    expect(heldByConfidence(0.85, 0.4)).toBe(true);
  });
  it("writes a model row at/above the threshold", () => {
    expect(heldByConfidence(0.85, 0.85)).toBe(false);
    expect(heldByConfidence(0.85, 0.99)).toBe(false);
  });
  it("never holds structured rows (null confidence) or thresholdless jobs (null)", () => {
    expect(heldByConfidence(0.85, null)).toBe(false);
    expect(heldByConfidence(null, 0.1)).toBe(false);
  });
});
