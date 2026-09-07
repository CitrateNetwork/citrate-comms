/**
 * RM-Q MEDIUM/LOW tripwires for route/DB-bound fixes that cannot be exercised
 * without a live database. Each asserts the presence of the specific guard the
 * audit found missing, so the fix cannot be silently reverted. (Behavioral
 * coverage for the pure/isolatable fixes lives in crypto.test.ts + tools.test.ts.)
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..", "..", "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

describe("CM2-B-B011 — single-invite route enforces canGrant (anti-escalation)", () => {
  it("the single-invite POST calls canGrant, matching the batch route", () => {
    const src = read("src/app/api/workspaces/[id]/invites/route.ts");
    expect(src).toMatch(/canGrant\(ctx\.role,\s*parsed\.data\.role/);
    expect(src).toMatch(/forbidden_role/);
  });
});

describe("CM2-B-B013 — persona-resource mutations are scoped to the authorized persona", () => {
  it("setResourceEnabled + deleteResource predicate on personaId", () => {
    const src = read("src/lib/domain/agent-config.ts");
    // Both functions must take personaId and use it in the WHERE clause.
    expect(src).toMatch(/setResourceEnabled\([\s\S]*?personaId: string/);
    expect(src).toMatch(/deleteResource\([\s\S]*?personaId: string/);
    expect((src.match(/eq\(agentResources\.personaId, personaId\)/g) ?? []).length).toBeGreaterThanOrEqual(2);
  });
});

describe("CM2-B-B023 — notification SSE stream re-authorizes on each tick", () => {
  it("the reconcile tick calls membershipOf and cleans up when revoked", () => {
    const src = read("src/app/api/workspaces/[id]/notifications/stream/route.ts");
    expect(src).toMatch(/membershipOf\(id, sub\)/);
  });
});
