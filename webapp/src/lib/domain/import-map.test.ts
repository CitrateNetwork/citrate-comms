import { describe, it, expect } from "vitest";
import { suggestMapping, columnsFor, slugKey } from "./import-map";
import type { ParsedColumn } from "./import-parse";

function col(name: string, type: ParsedColumn["type"], sensitive = false): ParsedColumn {
  return { name, type, sensitive, nullFrac: 0, samples: [] };
}

describe("suggestMapping — ZoomInfo-style contact export", () => {
  const cols: ParsedColumn[] = [
    col("First Name", "text"),
    col("Last Name", "text"),
    col("Email Address", "email", true),
    col("Job Title", "text"),
    col("Company Name", "text"),
    col("Website", "url"),
    col("Archetype", "select"),
    col("Management Level", "select"),
  ];
  const spec = suggestMapping(cols);

  it("routes the standard columns", () => {
    expect(columnsFor(spec, "contact.firstName")).toEqual(["First Name"]);
    expect(columnsFor(spec, "contact.lastName")).toEqual(["Last Name"]);
    expect(columnsFor(spec, "contact.email")).toEqual(["Email Address"]);
    expect(columnsFor(spec, "contact.title")).toEqual(["Job Title"]);
    expect(columnsFor(spec, "account.name")).toEqual(["Company Name"]);
    expect(columnsFor(spec, "account.domain")).toEqual(["Website"]);
  });

  it("picks contact primary + email dedupe", () => {
    expect(spec.primaryEntity).toBe("contact");
    expect(spec.dedupe.contact).toBe("email");
    expect(spec.dedupe.account).toBe("domain");
  });

  it("sends unmapped columns to custom fields on the primary entity", () => {
    const arche = spec.columns.find((c) => c.column === "Archetype")!;
    expect(arche.map.kind).toBe("custom");
    if (arche.map.kind === "custom") {
      expect(arche.map.entity).toBe("contact");
      expect(arche.map.key).toBe("archetype");
    }
  });

  it("only claims a singular target once", () => {
    // Two email-ish columns → only the first is contact.email; the rest custom.
    const two = suggestMapping([col("Email", "email", true), col("Secondary Email", "email", true)]);
    expect(columnsFor(two, "contact.email").length).toBe(1);
  });
});

describe("slugKey", () => {
  it("produces stable machine keys", () => {
    expect(slugKey("Prior Exits / Liquidity")).toBe("prior_exits_liquidity");
    expect(slugKey("  ")).toBe("field");
  });
});
