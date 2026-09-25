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
 * The second suite covers EVERY OTHER route family under /api:
 * channel-scoped routes (capability AND seat in the channel), channel creation, join,
 * the workspace list, bearer-only machine routes and the public unsubscribe surface.
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
import { createChannel } from "@/lib/domain/channels";
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

let discovered: { key: string; method: string; handler: Handler }[] | null = null;
/** Import every route module once (slow on a loaded machine — hence the long timeouts). */
async function discover(): Promise<{ key: string; method: string; handler: Handler }[]> {
  if (discovered) return discovered;
  const out: { key: string; method: string; handler: Handler }[] = [];
  for (const [file, load] of Object.entries(modules)) {
    const mod = (await load()) as Record<string, unknown>;
    const key = routeKey(file);
    for (const m of METHODS) if (typeof mod[m] === "function") out.push({ key, method: m, handler: mod[m] as Handler });
  }
  discovered = out;
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
  }, 180_000);

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
  }, 300_000);

  it("external roles hold no workspace-data capability (matrix invariant)", () => {
    for (const r of ["Partner", "Guest"] as Role[]) {
      expect(can(r, C.ReadWorkspace)).toBe(false);
      expect(can(r, C.CreateRecord)).toBe(false);
    }
    for (const r of ["Owner", "Admin", "Member", "Agent"] as Role[]) expect(can(r, C.ReadWorkspace)).toBe(true);
  });
});

// ── Every other /api route family ──────────────────────────────────────────────
type OtherPolicy =
  | { kind: "channel"; cap: Capability } // requireChannel: capability AND seated in the channel
  | { kind: "create-channel" } // CreateChannel (channel/forum) / CreateDirectMessage (dm)
  | { kind: "authenticated" } // any signed-in identity (member or not); anonymous 401
  | { kind: "bearer"; env: string } // machine route: shared secret only, never a session
  | { kind: "public-token" }; // unauthenticated by design; the signed token is the gate

const OTHER_POLICY: Record<string, OtherPolicy> = {
  "channels/[id]/agent-reply POST": { kind: "channel", cap: C.PostMessage },
  "channels/[id]/ledger GET": { kind: "channel", cap: C.ReadChannel },
  "channels/[id]/ledger POST": { kind: "channel", cap: C.PostMessage },
  "channels/[id]/ledger PATCH": { kind: "channel", cap: C.PostMessage },
  "channels/[id]/members POST": { kind: "channel", cap: C.AddMember },
  "channels/[id]/messages GET": { kind: "channel", cap: C.ReadChannel },
  "channels/[id]/messages POST": { kind: "channel", cap: C.PostMessage },
  "channels/[id]/pin GET": { kind: "channel", cap: C.ReadChannel },
  "channels/[id]/pin POST": { kind: "channel", cap: C.PostMessage },
  "channels/[id]/read POST": { kind: "channel", cap: C.ReadChannel },
  "channels POST": { kind: "create-channel" },
  "join POST": { kind: "authenticated" },
  "workspaces GET": { kind: "authenticated" },
  "workspaces POST": { kind: "authenticated" },
  "cron/import-tick GET": { kind: "bearer", env: "CRON_SECRET" },
  "cron/reminders GET": { kind: "bearer", env: "CRON_SECRET" },
  "ops/crm-dedupe POST": { kind: "bearer", env: "DEDUPE_OPS_SECRET" },
  "unsubscribe GET": { kind: "public-token" },
  "unsubscribe POST": { kind: "public-token" },
};

const otherModules = import.meta.glob("../app/api/**/route.ts");
const API = "../app/api/";

async function discoverOther(): Promise<{ key: string; method: string; handler: (req: Request, ctx: { params: Promise<Record<string, string>> }) => Promise<Response> }[]> {
  const out: { key: string; method: string; handler: (req: Request, ctx: { params: Promise<Record<string, string>> }) => Promise<Response> }[] = [];
  for (const [file, load] of Object.entries(otherModules)) {
    if (file.startsWith(ROOT)) continue; // covered by the workspace matrix above
    const key = file.slice(API.length).replace(/\/?route\.ts$/, "");
    const mod = (await load()) as Record<string, unknown>;
    for (const m of METHODS) if (typeof mod[m] === "function") out.push({ key, method: m, handler: mod[m] as never });
  }
  return out;
}

describe("route x role matrix — every other /api route family", () => {
  let seated: string, unseated: string, foreign: string, otherWs: string;
  beforeAll(async () => {
    await addMember(ws, "rrcreator", "Member");
    seated = (await createChannel({ workspaceId: ws, kind: "channel", name: `all-${run}`, createdBySub: sub(whoFor("Owner")), memberSubs: ROLES.map((r) => sub(whoFor(r))) })).id;
    unseated = (await createChannel({ workspaceId: ws, kind: "channel", name: `none-${run}`, createdBySub: sub("rrcreator") })).id;
    otherWs = (await createWorkspace({ name: `rr-other ${run}`, ownerSub: sub("rrstranger"), ownerWallet: null, ownerEmail: null })).id;
    foreign = (await createChannel({ workspaceId: otherWs, kind: "channel", name: "f", createdBySub: sub("rrstranger") })).id;
  });

  it("every handler outside /api/workspaces/[id] has a declared policy (and no stale ones)", async () => {
    const found = (await discoverOther()).map((h) => `${h.key} ${h.method}`);
    const declared = Object.keys(OTHER_POLICY);
    expect(found.filter((f) => !declared.includes(f)), "undeclared handlers — add an OTHER_POLICY entry").toEqual([]);
    expect(declared.filter((d) => !found.includes(d)), "stale OTHER_POLICY entries").toEqual([]);
  }, 180_000);

  it("each handler admits exactly the callers its policy admits", async () => {
    const failures: string[] = [];
    const call = async (h: { handler: (req: Request, ctx: { params: Promise<Record<string, string>> }) => Promise<Response> }, method: string, url: string, who: string | null, params: Record<string, string>, body?: unknown, headers: Record<string, string> = {}) => {
      const init: RequestInit = { method, headers };
      if (method !== "GET") init.body = JSON.stringify(body ?? {});
      const res = await h.handler(req(url, who, init), { params: Promise.resolve(params) });
      await res.body?.cancel().catch(() => undefined);
      return res.status;
    };
    const refused = (st: number) => st === 401 || st === 403;
    for (const h of await discoverOther()) {
      const p = OTHER_POLICY[`${h.key} ${h.method}`]!;
      const tag = `${h.method} ${h.key}`;
      if (p.kind === "channel") {
        for (const role of ROLES) {
          const ok = can(role, p.cap);
          const st = await call(h, h.method, `/api/channels/${seated}`, whoFor(role), { id: seated });
          if (ok && refused(st)) failures.push(`${tag} seated ${role}: expected admitted, got ${st}`);
          if (!ok && st !== 403) failures.push(`${tag} seated ${role}: expected 403, got ${st}`);
          for (const [label, ch] of [["unseated", unseated], ["foreign-workspace", foreign]] as const) {
            const s2 = await call(h, h.method, `/api/channels/${ch}`, whoFor(role), { id: ch });
            if (s2 !== 403) failures.push(`${tag} ${label} ${role}: expected 403, got ${s2}`);
          }
        }
        const anon = await call(h, h.method, `/api/channels/${seated}`, null, { id: seated });
        if (!refused(anon)) failures.push(`${tag} anonymous: expected 401/403, got ${anon}`);
      } else if (p.kind === "create-channel") {
        for (const role of ROLES) {
          for (const [kind, cap] of [["channel", C.CreateChannel], ["forum", C.CreateChannel], ["dm", C.CreateDirectMessage]] as const) {
            const st = await call(h, "POST", "/api/channels", whoFor(role), {}, { workspaceId: ws, kind, name: `c-${kind}-${role}`.toLowerCase() });
            const ok = can(role, cap);
            if (ok && refused(st)) failures.push(`${tag} ${kind} ${role}: expected admitted, got ${st}`);
            if (!ok && st !== 403) failures.push(`${tag} ${kind} ${role}: expected 403, got ${st}`);
          }
          const f = await call(h, "POST", "/api/channels", whoFor(role), {}, { workspaceId: otherWs, kind: "dm", name: "x" });
          if (f !== 403) failures.push(`${tag} foreign workspace ${role}: expected 403, got ${f}`);
        }
        const anon = await call(h, "POST", "/api/channels", null, {}, { workspaceId: ws, kind: "dm", name: "x" });
        if (!refused(anon)) failures.push(`${tag} anonymous: expected 401/403, got ${anon}`);
      } else if (p.kind === "authenticated") {
        for (const who of [...ROLES.map(whoFor), "rrnonmember"]) {
          const st = await call(h, h.method, `/api/${h.key}`, who, {}, h.key === "join" ? { token: "x".repeat(40) } : { name: `rr ${who}` });
          if (refused(st)) failures.push(`${tag} ${who}: expected admitted, got ${st}`);
        }
        const anon = await call(h, h.method, `/api/${h.key}`, null, {});
        if (anon !== 401) failures.push(`${tag} anonymous: expected 401, got ${anon}`);
      } else if (p.kind === "bearer") {
        const prev = process.env[p.env];
        process.env[p.env] = "rr-machine-token";
        try {
          for (const who of [...ROLES.map(whoFor), null]) {
            const st = await call(h, h.method, `/api/${h.key}`, who, {});
            if (st !== 401) failures.push(`${tag} session ${who ?? "anonymous"}: expected 401 (bearer only), got ${st}`);
          }
          const wrong = await call(h, h.method, `/api/${h.key}`, null, {}, { dryRun: true }, { authorization: "Bearer nope" });
          if (wrong !== 401) failures.push(`${tag} wrong bearer: expected 401, got ${wrong}`);
          const right = await call(h, h.method, `/api/${h.key}`, null, {}, { dryRun: true, workspaceId: ws }, { authorization: "Bearer rr-machine-token" });
          if (refused(right)) failures.push(`${tag} correct bearer: expected admitted, got ${right}`);
        } finally {
          if (prev === undefined) delete process.env[p.env];
          else process.env[p.env] = prev;
        }
      } else {
        // public-token: identity is irrelevant; a bad token never succeeds and never 5xx's
        const statuses = new Set<number>();
        for (const who of [...ROLES.map(whoFor), null]) statuses.add(await call(h, h.method, `/api/${h.key}?u=invalid`, who, {}));
        if (statuses.size !== 1) failures.push(`${tag}: outcome depends on identity (${[...statuses].join(",")})`);
        const st = [...statuses][0]!;
        if (h.method === "POST" && st !== 400) failures.push(`${tag}: invalid token expected 400, got ${st}`);
        if (h.method === "GET" && st !== 303) failures.push(`${tag}: expected 303 to the confirmation page, got ${st}`);
      }
    }
    expect(failures).toEqual([]);
  }, 300_000);
});
