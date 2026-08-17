import { beforeAll, describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolveRow, type Upserter } from "./import-engine";
import { suggestMapping, type MappingSpec } from "./import-map";
import { parseWorkbook } from "./import-parse";

beforeAll(() => {
  process.env.COMMS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
});

/** In-memory upserter mirroring the real dedupe rules, for DB-free verification. */
function fakeUpserter() {
  let n = 0;
  const id = () => `r${++n}`;
  const accByKey = new Map<string, string>();
  const contactByEmail = new Map<string, string>();
  const contactByName = new Map<string, string>();
  const counts = { accounts: 0, contacts: 0, deals: 0, tasks: 0, customs: 0 };
  const customs: { entity: string; key: string; value: string }[] = [];
  const up: Upserter = {
    async upsertAccount(name, domain) {
      const k = (domain || name || "").toLowerCase();
      if (!k) return null;
      if (accByKey.has(k)) return { id: accByKey.get(k)!, created: false };
      const i = id();
      accByKey.set(k, i);
      counts.accounts++;
      return { id: i, created: true };
    },
    async upsertContact(name, _title, email, accountId) {
      const ek = email?.trim().toLowerCase();
      if (ek && contactByEmail.has(ek)) return { id: contactByEmail.get(ek)!, created: false };
      const nk = `${name.toLowerCase()}|${accountId ?? ""}`;
      if (!ek && contactByName.has(nk)) return { id: contactByName.get(nk)!, created: false };
      const i = id();
      if (ek) contactByEmail.set(ek, i);
      contactByName.set(nk, i);
      counts.contacts++;
      return { id: i, created: true };
    },
    async createDealFor() {
      counts.deals++;
    },
    async createTaskFor() {
      counts.tasks++;
    },
    async setCustom(entity, _recordId, key, _label, _type, value) {
      counts.customs++;
      customs.push({ entity, key, value });
    },
  };
  return { up, counts, customs };
}

const SPEC: MappingSpec = {
  primaryEntity: "contact",
  dedupe: { account: "domain", contact: "email" },
  columns: [
    { column: "Name", map: { kind: "std", target: "contact.name" } },
    { column: "Email", map: { kind: "std", target: "contact.email" } },
    { column: "Title", map: { kind: "std", target: "contact.title" } },
    { column: "Company", map: { kind: "std", target: "account.name" } },
    { column: "Website", map: { kind: "std", target: "account.domain" } },
    { column: "Archetype", map: { kind: "custom", entity: "contact", key: "archetype", label: "Archetype", type: "select" } },
    { column: "Phone", map: { kind: "std", target: "contact.phone" } },
  ],
};

describe("resolveRow — routing, dedupe, held", () => {
  it("creates an account + contact + custom field for a full row", async () => {
    const { up, counts, customs } = fakeUpserter();
    const o = await resolveRow(SPEC, { Name: "Jane Roe", Email: "jane@acme.com", Title: "CEO", Company: "Acme", Website: "acme.com", Archetype: "Operator", Phone: "+1 555 123 4567" }, up);
    expect(o).toBe("created");
    expect(counts.accounts).toBe(1);
    expect(counts.contacts).toBe(1);
    expect(customs.find((c) => c.key === "archetype")?.value).toBe("Operator");
    // phone routed to an encrypted custom field, not lost
    expect(customs.find((c) => c.key === "phone")?.value).toBe("+1 555 123 4567");
  });

  it("dedupes contacts by email and accounts by domain across rows", async () => {
    const { up, counts } = fakeUpserter();
    await resolveRow(SPEC, { Name: "Jane Roe", Email: "jane@acme.com", Company: "Acme", Website: "acme.com" }, up);
    // same email, different display name → same contact (updated, not created)
    const o2 = await resolveRow(SPEC, { Name: "J. Roe", Email: "JANE@acme.com", Company: "Acme", Website: "acme.com" }, up);
    // second acme contact, new email → new contact but SAME account
    const o3 = await resolveRow(SPEC, { Name: "Sam Lee", Email: "sam@acme.com", Company: "Acme", Website: "acme.com" }, up);
    expect(o2).toBe("updated");
    expect(o3).toBe("created");
    expect(counts.accounts).toBe(1); // acme.com deduped
    expect(counts.contacts).toBe(2); // jane + sam
  });

  it("holds a row with no usable identity", async () => {
    const { up } = fakeUpserter();
    const o = await resolveRow(SPEC, { Title: "", Archetype: "" }, up);
    expect(o).toBe("held");
  });

  it("creates a task when the mapping asks for one", async () => {
    const { up, counts } = fakeUpserter();
    const spec: MappingSpec = { ...SPEC, createTasks: { projectName: "Outreach" } };
    await resolveRow(spec, { Name: "Jane Roe", Email: "jane@acme.com", Company: "Acme", Website: "acme.com" }, up);
    expect(counts.tasks).toBe(1);
  });
});

const MASTER = "/Users/learnlikelarry/Downloads/Investor_Master_Universe_Recalibrated_2026-08-15.xlsx";
describe("resolveRow — real-file scale (1,000+ rows, no DB, no overwhelm)", () => {
  const run = existsSync(MASTER) ? it : it.skip;
  run("routes the whole Master Universe sheet through the resolver", async () => {
    const wb = await parseWorkbook(readFileSync(MASTER), MASTER);
    const sheet = wb.sheets.find((s) => s.name === "Master Universe")!;
    const spec = suggestMapping(sheet.columns);
    const { up, counts } = fakeUpserter();
    let created = 0, updated = 0, held = 0;
    for (const row of sheet.rows) {
      const o = await resolveRow(spec, row, up);
      if (o === "created") created++;
      else if (o === "updated") updated++;
      else held++;
    }
    expect(sheet.rows.length).toBeGreaterThan(900);
    expect(created + updated + held).toBe(sheet.rows.length);
    // A ZoomInfo export should produce many contacts and fewer (deduped) accounts.
    expect(counts.contacts).toBeGreaterThan(500);
    expect(counts.accounts).toBeLessThanOrEqual(counts.contacts);
    // eslint-disable-next-line no-console
    console.log(`Master Universe: ${sheet.rows.length} rows → ${counts.contacts} contacts, ${counts.accounts} accounts, ${held} held`);
  });
});
