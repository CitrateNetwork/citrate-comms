import { describe, it, expect } from "vitest";
import { parseWorkbook, summarizeParsed, isTabularFile } from "./import-parse";

const CSV = [
  "Name,Email Address,Company,Website,Job Title,Archetype,Deal Value",
  "Jane Roe,jane@acme.com,Acme Inc,acme.com,CEO,Operator,$1200000",
  "John Doe,john@beta.io,Beta LLC,beta.io,CTO,Builder,$800000",
  "Sam Lee,sam@acme.com,Acme Inc,acme.com,VP,Operator,$500000",
  "Pat Kim,pat@gamma.co,Gamma,gamma.co,Founder,Builder,$2000000",
  "Mia Fox,mia@delta.dev,Delta,delta.dev,COO,Operator,$300000",
  "Ravi Rao,ravi@zeta.ai,Zeta,zeta.ai,CEO,Builder,$900000",
].join("\n");

describe("parseWorkbook — type inference + sensitivity", () => {
  it("infers types and flags PII columns", async () => {
    const wb = await parseWorkbook(Buffer.from(CSV), "leads.csv");
    expect(wb.sheets.length).toBe(1);
    const sheet = wb.sheets[0]!;
    expect(sheet.rows.length).toBe(6);
    const byName = new Map(sheet.columns.map((c) => [c.name, c]));

    expect(byName.get("Email Address")!.type).toBe("email");
    expect(byName.get("Email Address")!.sensitive).toBe(true);
    expect(byName.get("Website")!.type).toBe("url");
    expect(byName.get("Company")!.sensitive).toBe(false);
    expect(byName.get("Deal Value")!.type).toBe("currency");
    expect(byName.get("Archetype")!.type).toBe("select");
  });

  it("keeps sensitive column values OUT of samples", async () => {
    const wb = await parseWorkbook(Buffer.from(CSV), "leads.csv");
    const email = wb.sheets[0]!.columns.find((c) => c.name === "Email Address")!;
    expect(email.samples).toEqual([]); // never sampled
    const company = wb.sheets[0]!.columns.find((c) => c.name === "Company")!;
    expect(company.samples.length).toBeGreaterThan(0);
  });

  it("summarizeParsed masks sensitive columns and stays compact", async () => {
    const wb = await parseWorkbook(Buffer.from(CSV), "leads.csv");
    const summary = summarizeParsed(wb);
    expect(summary).toContain("6 rows");
    expect(summary).not.toContain("jane@acme.com"); // sensitive value not leaked into RAG summary
    expect(summary).toContain("Acme Inc");
  });

  it("classifies file types", () => {
    expect(isTabularFile("x.xlsx", null)).toBe(true);
    expect(isTabularFile("x.csv", null)).toBe(true);
    expect(isTabularFile("notes.pdf", "application/pdf")).toBe(false);
    expect(isTabularFile("photo.png", "image/png")).toBe(false);
  });
});
