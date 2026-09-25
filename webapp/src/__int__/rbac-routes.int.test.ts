/**
 * Route x role authorization matrix (PBA-L3c-002 tripwire). Every handler under
 * /api/workspaces/[id]/** is DISCOVERED from the filesystem and must have a declared
 * policy below; each is then invoked as every role against a real Postgres, and the
 * outcome must match rbac/matrix.ts:
 *   - a role the policy refuses gets 403;
 *   - a role the policy admits is never refused by auth (no 401/403).
 * A new route, or a new method on an existing route, fails the "every handler is
 * declared" test until someone decides who may call it — deny-by-default review.
 *
 * Policies are capabilities from the matrix. "member" means any active member (the
 * handler scopes the data itself: own notifications/profile, attendee-scoped calendar,
 * channel-scoped documents, the roster, the role-filtered MCP surface). A function is
 * used only where the answer depends on an object the test cannot own (noted inline).
 */
import { describe, it, expect, vi, beforeAll } from "vitest";

vi.mock("@/lib/security/ratelimit", () => ({ limit: async () => ({ success: true, remaining: 99 }), rateLimitConfigured: () => true }));

import { Capability, can, ROLES, type Role } from "@/lib/rbac/matrix";
import { createWorkspace } from "@/lib/domain/workspaces";
import { listPersonas, seedDefaultPersonas } from "@/lib/domain/personas";
import { run, sub, req, addMember } from "./helpers";

type Policy = Capability | "member" | ((role: Role) => boolean);
const C = Capability;

const POLICY: Record<string, Policy> = {
  "accounts GET": C.ReadWorkspace,
  "accounts POST": C.CreateRecord,
  "agents/[agentId]/chat POST": C.ReadWorkspace,
  "agents/history GET": C.ReadWorkspace,
  "agents GET": C.ReadWorkspace,
  "agents POST": C.AddAgent,
  "agents PATCH": C.AddAgent,
  // Someone else's thread: only ManageWorkspace may read it (random thread id here).
  "agents/threads/[threadId]/messages GET": C.ManageWorkspace,
  "agents/threads GET": C.ReadWorkspace,
  "approvals GET": C.CreateRecord,
  "approvals POST": C.CreateRecord,
  "audit/verify POST": C.ReadWorkspace,
  "calendar/[eventId] GET": "member", // creator/attendee/admin only — 404 otherwise
  "calendar/[eventId] PATCH": C.CreateRecord,
  "calendar/[eventId] DELETE": C.CreateRecord,
  "calendar/[eventId]/rsvp POST": "member", // updates only the caller's own attendee row
  "calendar GET": "member", // attendee-scoped list
  "calendar POST": C.CreateRecord,
  "contacts GET": C.ReadWorkspace,
  "contacts POST": C.CreateRecord,
  "crm/[entity]/[recordId]/fields POST": C.CreateRecord,
  "crm/[entity]/[recordId]/notes POST": C.CreateRecord,
  "crm/[entity]/[recordId]/notes PATCH": C.CreateRecord,
  "crm/[entity]/[recordId] PATCH": C.CreateRecord,
  "crm/[entity]/[recordId] DELETE": C.DeleteRecord,
  "crm/[entity]/[recordId]/tags POST": C.CreateRecord,
  "crm/[entity]/[recordId]/tags DELETE": C.CreateRecord,
  "crm/[entity]/bulk-tag POST": C.CreateRecord,
  "crm/[entity]/records GET": C.ReadWorkspace,
  "crm/fields/[fieldId] PATCH": C.ManageWorkspace,
  "crm/fields/[fieldId] DELETE": C.ManageWorkspace,
  "crm/fields GET": C.ReadWorkspace,
  "crm/fields POST": C.ManageWorkspace,
  "crm/views GET": C.ReadWorkspace,
  "crm/views POST": C.CreateRecord,
  "crm/views DELETE": C.ReadWorkspace,
  "deals GET": C.ReadWorkspace,
  "deals POST": C.CreateRecord,
  "deals PATCH": C.CreateRecord,
  "documents/[docId]/download GET": "member", // per-document channel visibility (404/403)
  "documents/finalize POST": C.CreateRecord,
  "documents POST": C.CreateRecord,
  "documents/upload-token POST": C.CreateRecord,
  "import-jobs/[jobId] GET": C.ReadWorkspace,
  "import-jobs/[jobId]/tick POST": C.CreateRecord,
  "invites/batch POST": C.AddMember,
  "invites GET": C.AddMember,
  "invites POST": C.AddMember,
  "mcp GET": "member", // tool list filtered by role (external: channel-scoped tools only)
  "mcp POST": "member",
  "members GET": C.ReadChannel, // the roster (Partners start DMs from it)
  "members PATCH": C.AssignRole,
  "members DELETE": C.RemoveMember,
  "notifications GET": "member",
  "notifications POST": "member",
  "notifications/stream GET": "member",
  "persona-config-grants/[grantId] DELETE": C.ManageWorkspace,
  "persona-config-grants GET": C.ManageWorkspace,
  "persona-config-grants POST": C.ManageWorkspace,
  // Persona config: ManageWorkspace, or an INTERNAL member holding a grant (none here).
  "personas/[personaId]/clone POST": C.ManageWorkspace,
  "personas/[personaId]/prompts POST": C.ManageWorkspace,
  "personas/[personaId]/resources/[resourceId] PATCH": C.ManageWorkspace,
  "personas/[personaId]/resources/[resourceId] DELETE": C.ManageWorkspace,
  "personas/[personaId]/resources GET": C.ManageWorkspace,
  "personas/[personaId]/resources POST": C.ManageWorkspace,
  "personas/[personaId] GET": C.ManageWorkspace,
  "personas/[personaId] PATCH": C.ManageWorkspace,
  "personas/[personaId] DELETE": C.ManageWorkspace,
  "personas/[personaId]/skills POST": C.ManageWorkspace,
  "personas/import POST": C.ManageWorkspace,
  "personas GET": C.ReadWorkspace,
  "personas POST": C.ManageWorkspace,
  "profile PATCH": "member", // the caller's own display name / timezone
  "projects/[projectId] DELETE": C.DeleteRecord,
  "projects GET": C.ReadWorkspace,
  "projects POST": C.CreateRecord,
  "settings GET": "member", // workspace appearance/notification defaults (no data)
  "settings PATCH": C.ManageWorkspace,
  "tables/[sheetId]/import GET": C.ReadWorkspace,
  "tables/[sheetId]/import POST": C.CreateRecord,
  "tables/[sheetId]/mapping GET": C.ReadWorkspace,
  "tables/[sheetId]/mapping PUT": C.CreateRecord,
  "tables/[sheetId] GET": C.ReadWorkspace,
  "tables/[sheetId]/rows GET": C.ReadWorkspace,
  "tables GET": C.ReadWorkspace,
  "tasks/[taskId] PATCH": C.CreateRecord,
  "tasks/[taskId] DELETE": C.DeleteRecord,
  "tasks GET": C.ReadWorkspace,
  "tasks POST": C.CreateRecord,
  "tasks PATCH": C.CreateRecord,
};

const METHODS = ["GET", "POST", "PATCH", "PUT", "DELETE"] as const;
type Handler = (req: Request, ctx: { params: Promise<Record<string, string>> }) => Promise<Response>;

const modules = import.meta.glob("../app/api/workspaces/\\[id\\]/**/route.ts");
const ROOT = "../app/api/workspaces/[id]/";

function routeKey(file: string): string {
  const rel = file.slice(ROOT.length).replace(/\/?route\.ts$/, "");
  return rel;
}

const allowed = (p: Policy, role: Role) => (p === "member" ? true : typeof p === "function" ? p(role) : can(role, p));

let ws: string;
let personaId: string;
const whoFor = (role: Role) => `rr${role.toLowerCase()}`; // mock auth lowercases the dev address

beforeAll(async () => {
  ws = (await createWorkspace({ name: `rbac-routes ${run}`, ownerSub: sub(whoFor("Owner")), ownerWallet: null, ownerEmail: null })).id;
  for (const r of ROLES) if (r !== "Owner") await addMember(ws, whoFor(r), r);
  await seedDefaultPersonas(ws, sub(whoFor("Owner")));
  personaId = (await listPersonas(ws))[0]!.id;
});

function paramsFor(key: string): Record<string, string> {
  const p: Record<string, string> = { id: ws };
  for (const m of key.matchAll(/\[(\w+)\]/g)) {
    const name = m[1]!;
    p[name] = name === "personaId" ? personaId : name === "entity" ? "account" : crypto.randomUUID();
  }
  return p;
}

function bodyFor(key: string): string | undefined {
  if (key === "documents/upload-token") {
    return JSON.stringify({ type: "blob.generate-client-token", payload: { pathname: "x.txt", callbackUrl: "http://localhost/cb", clientPayload: null, multipart: false } });
  }
  return JSON.stringify({});
}

async function discover(): Promise<{ key: string; method: string; handler: Handler }[]> {
  const out: { key: string; method: string; handler: Handler }[] = [];
  for (const [file, load] of Object.entries(modules)) {
    const mod = (await load()) as Record<string, unknown>;
    const key = routeKey(file);
    for (const m of METHODS) if (typeof mod[m] === "function") out.push({ key, method: m, handler: mod[m] as Handler });
  }
  return out;
}

describe("route x role matrix matches rbac/matrix.ts (PBA-L3c-002 tripwire)", () => {
  it("discovers the workspace route tree", () => {
    expect(Object.keys(modules).length).toBeGreaterThan(40);
  });

  it("every handler has a declared policy, and every policy names a real handler", async () => {
    const found = (await discover()).map((h) => `${h.key || "(root)"} ${h.method}`.replace(/^\(root\) /, ""));
    const declared = Object.keys(POLICY);
    expect(found.filter((f) => !declared.includes(f)), "undeclared handlers — add a POLICY entry").toEqual([]);
    expect(declared.filter((d) => !found.includes(d)), "stale POLICY entries").toEqual([]);
  });

  it("each handler admits exactly the roles its policy admits", async () => {
    const failures: string[] = [];
    for (const { key, method, handler } of await discover()) {
      const policy = POLICY[`${key} ${method}`]!;
      for (const role of ROLES) {
        const url = `/api/workspaces/${ws}/${key}`;
        const init: RequestInit = { method };
        if (method !== "GET") init.body = bodyFor(key);
        let res: Response;
        try {
          res = await handler(req(url, whoFor(role), init), { params: Promise.resolve(paramsFor(key)) });
        } catch (e) {
          failures.push(`${method} ${key} as ${role}: threw ${(e as Error).message}`);
          continue;
        }
        await res.body?.cancel().catch(() => undefined); // never leave an SSE stream open
        const ok = allowed(policy, role);
        if (ok && (res.status === 401 || res.status === 403)) failures.push(`${method} ${key} as ${role}: expected admitted, got ${res.status}`);
        if (!ok && res.status !== 403) failures.push(`${method} ${key} as ${role}: expected 403, got ${res.status}`);
      }
      // Unauthenticated callers are always refused.
      const anon = await handler(req(`/api/workspaces/${ws}/${key}`, null, method === "GET" ? { method } : { method, body: bodyFor(key) }), { params: Promise.resolve(paramsFor(key)) });
      await anon.body?.cancel().catch(() => undefined);
      if (anon.status !== 401 && anon.status !== 403) failures.push(`${method} ${key} anonymous: expected 401/403, got ${anon.status}`);
    }
    expect(failures).toEqual([]);
  });

  it("external roles hold no workspace-data capability (matrix invariant)", () => {
    for (const r of ["Partner", "Guest"] as Role[]) {
      expect(can(r, C.ReadWorkspace)).toBe(false);
      expect(can(r, C.CreateRecord)).toBe(false);
    }
    for (const r of ["Owner", "Admin", "Member", "Agent"] as Role[]) expect(can(r, C.ReadWorkspace)).toBe(true);
  });
});
