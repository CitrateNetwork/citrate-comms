import { NextResponse } from "next/server";
import { bearerMatches } from "@/lib/security/bearer";
import { db } from "@/lib/db/client";
import { workspaces } from "@/lib/db/schema";
import { dedupeWorkspaceCrm, type DedupeReport } from "@/lib/domain/crm-dedupe";

export const runtime = "nodejs";
export const maxDuration = 300; // large cleanups run in batches; give each batch headroom

/**
 * Ops-only CRM de-dup runner. Gated by a bearer secret (DEDUPE_OPS_SECRET) — if that env
 * is unset the route is INERT (404), so it carries no attack surface at rest. Used once
 * to clean up production after a messy import; ordinary de-dup goes through the crm.dedupe
 * agent tool / approvals. Body: { dryRun?: boolean, workspaceId?: string } — omit
 * workspaceId to sweep every workspace.
 */
export async function POST(req: Request) {
  const secret = process.env.DEDUPE_OPS_SECRET;
  if (!secret) return NextResponse.json({ error: "not_found" }, { status: 404 });
  const auth = req.headers.get("authorization") || "";
  if (!bearerMatches(auth, secret)) return NextResponse.json({ error: "unauthorized" }, { status: 401 }); // PBA-L3c-035

  const body = (await req.json().catch(() => ({}))) as { dryRun?: boolean; workspaceId?: string; maxMerges?: number };
  const dryRun = body.dryRun ?? true; // default SAFE: dry-run unless explicitly told to execute
  const maxMerges = body.maxMerges ?? 400; // per-workspace batch cap; caller loops until totals hit 0

  const targets = body.workspaceId
    ? [{ id: body.workspaceId }]
    : await db().select({ id: workspaces.id }).from(workspaces);

  const results: Record<string, DedupeReport> = {};
  for (const w of targets) {
    results[w.id] = await dedupeWorkspaceCrm(w.id, { dryRun, actorSub: "ops:crm-dedupe", maxMerges });
  }
  const totals = Object.values(results).reduce(
    (t, r) => ({ accounts: t.accounts + r.accounts.merged, deals: t.deals + r.deals.merged, contacts: t.contacts + r.contacts.merged }),
    { accounts: 0, deals: 0, contacts: 0 },
  );
  return NextResponse.json({ dryRun, workspaces: targets.length, totals, results });
}
