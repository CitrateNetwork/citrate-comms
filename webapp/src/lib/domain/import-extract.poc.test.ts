/**
 * UDI Phase 1 PoC (PLANSET 10, gate G5). A readable, DB-free demonstration of the
 * "Read → Bridge → gate" path for a free-form TEXT BLOCK requiring NLP extraction
 * and for a semi-structured JSON dump. The live end-to-end (real gateway + DB write)
 * runs in the deployed workspace; here we pin the model output to prove the pipeline
 * shape deterministically. The CSV/xlsx and PDF-text legs are covered by
 * import-engine.test.ts and documents.ts (unpdf) respectively.
 */
import { describe, it, expect } from "vitest";
import { extractEntities, recordToCells } from "./import-extract";
import { heldByConfidence } from "./import-engine";

const THRESHOLD = 0.85;

describe("PoC: text block requiring NLP extraction", () => {
  const note = [
    "Call notes — 2026-08-18. Spoke with Dana Kim, VP Engineering at Northwind Labs",
    "(northwindlabs.io). They want the Enterprise plan; budget around $120,000 for the year.",
    "Next step: send the MSA by Friday. Dana's email is dana.kim@northwindlabs.io.",
    "Also vaguely mentioned a sister company 'Breeze' but wasn't sure of the name.",
  ].join(" ");

  it("extracts entities with per-record confidence and routes by the gate", async () => {
    // Pinned model output: one high-confidence record + one low-confidence guess.
    const res = await extractEntities(note, {
      doExtract: async () => ({
        records: [
          { account: { name: "Northwind Labs", domain: "northwindlabs.io" }, contact: { name: "Dana Kim", title: "VP Engineering", email: "dana.kim@northwindlabs.io" }, deal: { name: "Enterprise plan", value: "$120,000" }, task: { title: "Send the MSA by Friday" }, confidence: 0.93 },
          { account: { name: "Breeze" }, confidence: 0.35 },
        ],
      }),
    });

    expect(res.source).toBe("model");
    expect(res.records).toHaveLength(2);

    const routed = res.records.map((r) => ({ cells: recordToCells(r), held: heldByConfidence(THRESHOLD, r.confidence) }));

    // The confident record auto-writes with a full CRM entity set...
    const written = routed.filter((r) => !r.held);
    expect(written).toHaveLength(1);
    expect(written[0]!.cells["account.name"]).toBe("Northwind Labs");
    expect(written[0]!.cells["contact.email"]).toBe("dana.kim@northwindlabs.io");
    expect(written[0]!.cells["deal.value"]).toBe("$120,000");
    expect(written[0]!.cells["task.title"]).toContain("MSA");

    // ...the shaky "Breeze" guess is HELD for human review, never auto-written.
    const held = routed.filter((r) => r.held);
    expect(held).toHaveLength(1);
    expect(held[0]!.cells["account.name"]).toBe("Breeze");
  });
});

describe("PoC: semi-structured JSON dump (deterministic, no model)", () => {
  it("maps records at confidence 1.0 and writes them all", async () => {
    const dump = JSON.stringify([
      { company: "Acme", website: "acme.com", name: "Jane Roe", email: "jane@acme.com", role: "CEO", amount: "$50k" },
      { company: "Globex", name: "John Doe", email: "john@globex.com" },
    ]);
    const res = await extractEntities(dump);
    expect(res.source).toBe("json");
    expect(res.records).toHaveLength(2);
    expect(res.records.every((r) => !heldByConfidence(THRESHOLD, r.confidence))).toBe(true);
  });
});
