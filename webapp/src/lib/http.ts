/**
 * Small HTTP helpers for route handlers — turn GuardError into the right status and
 * keep route bodies focused on the happy path.
 */
import { NextResponse } from "next/server";
import { GuardError } from "@/lib/tenant/guard";
import { cookieValue, ID_COOKIE, REFRESH_COOKIE } from "@/lib/auth/cookies";

/** Convert a thrown error into a JSON response (GuardError → its status, else 500). */
export function errorResponse(e: unknown): NextResponse {
  if (e instanceof GuardError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error("[route] unhandled error", e);
  return NextResponse.json({ error: "internal_error" }, { status: 500 });
}

/** A JSON media type (application/json or application/*+json), parameters ignored. */
export function isJsonContentType(ct: string | null): boolean {
  const t = (ct ?? "").split(";")[0]!.trim().toLowerCase();
  return t === "application/json" || (t.startsWith("application/") && t.endsWith("+json"));
}

/**
 * Parse + safely return JSON body, or null on malformed input. PBA-L3c-026: a request
 * that rides the session cookie must declare a JSON content-type — a CORS-simple
 * `text/plain` body (what a cross-site form can send without a preflight) is refused
 * (null → the route's 400), independently of the proxy's Origin gate.
 */
export async function readJson(req: Request): Promise<unknown | null> {
  const cookieAuth = Boolean(cookieValue(req, ID_COOKIE) || cookieValue(req, REFRESH_COOKIE));
  if (cookieAuth && !req.headers.get("authorization") && !isJsonContentType(req.headers.get("content-type"))) return null;
  try {
    return await req.json();
  } catch {
    return null;
  }
}
