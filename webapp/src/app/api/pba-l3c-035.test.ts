/**
 * PBA-L3c-035 misc hardening: GET unsubscribe is side-effect free, logout revokes the
 * refresh token at the authority, and the cron route's bearer check is exact.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const suppress = vi.fn(async () => undefined);
const runDueReminders = vi.fn(async () => ({ sent: 0, skipped: 0 }));
vi.mock("@/lib/email/suppression", () => ({ suppress: (...a: unknown[]) => suppress(...(a as [])) }));
vi.mock("@/lib/security/crypto", async (o) => ({ ...(await o()), verifyUnsubscribeToken: (t: string) => (t === "good" ? "a@b.co" : null) }));
vi.mock("@/lib/domain/calendar", () => ({ runDueReminders: () => runDueReminders() }));

import * as unsub from "@/app/api/unsubscribe/route";
import * as logout from "@/app/auth/logout/route";
import * as cron from "@/app/api/cron/reminders/route";

describe("PBA-L3c-035", () => {
  beforeEach(() => {
    suppress.mockClear();
    runDueReminders.mockClear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("GET /api/unsubscribe changes nothing and hands the token to the confirmation page", async () => {
    const r = await unsub.GET(new Request("https://comms.example/api/unsubscribe?u=good"));
    expect(r.status).toBe(303);
    expect(r.headers.get("location")).toBe("https://comms.example/unsubscribe?u=good");
    expect(suppress).not.toHaveBeenCalled();
    // the POST (confirmation page / RFC 8058 one-click) still suppresses
    const p = await unsub.POST(new Request("https://comms.example/api/unsubscribe?u=good", { method: "POST" }));
    expect(p.status).toBe(200);
    expect(suppress).toHaveBeenCalledOnce();
  });

  it("logout revokes the refresh token at the authority, then clears cookies", async () => {
    process.env.OIDC_ISSUER = "https://auth.example/oidc";
    const calls: { url: string; body: string }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, body: String(init.body) });
      return new Response(null, { status: 200 });
    }));
    const r = await logout.POST(new Request("https://comms.example/auth/logout", { method: "POST", headers: { cookie: "cc_oidc_refresh=RT-123" } }));
    expect(r.status).toBe(303);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://auth.example/oidc/token/revocation");
    expect(calls[0]!.body).toContain("token=RT-123");
    expect(calls[0]!.body).toContain("token_type_hint=refresh_token");
    expect(r.headers.get("set-cookie")).toContain("cc_oidc_refresh=");
    delete process.env.OIDC_ISSUER;
  });

  it("logout still signs out when the authority is unreachable", async () => {
    process.env.OIDC_ISSUER = "https://auth.example/oidc";
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("down");
    }));
    const r = await logout.POST(new Request("https://comms.example/auth/logout", { method: "POST", headers: { cookie: "cc_oidc_refresh=RT" } }));
    expect(r.status).toBe(303);
    delete process.env.OIDC_ISSUER;
  });

  it("cron route: exact bearer only", async () => {
    process.env.CRON_SECRET = "cron-s3cret";
    const bad = await cron.GET(new Request("https://x/api/cron/reminders", { headers: { authorization: "Bearer cron-s3cre" } }));
    expect(bad.status).toBe(401);
    expect(runDueReminders).not.toHaveBeenCalled();
    const ok = await cron.GET(new Request("https://x/api/cron/reminders", { headers: { authorization: "Bearer cron-s3cret" } }));
    expect(ok.status).toBe(200);
    delete process.env.CRON_SECRET;
  });
});
