/**
 * Small HTTP helpers for route handlers — turn GuardError into the right status and
 * keep route bodies focused on the happy path.
 */
import { NextResponse } from "next/server";
import { GuardError } from "@/lib/tenant/guard";

/** Convert a thrown error into a JSON response (GuardError → its status, else 500). */
export function errorResponse(e: unknown): NextResponse {
  if (e instanceof GuardError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error("[route] unhandled error", e);
  return NextResponse.json({ error: "internal_error" }, { status: 500 });
}

/** Parse + safely return JSON body, or null on malformed input. */
export async function readJson(req: Request): Promise<unknown | null> {
  try {
    return await req.json();
  } catch {
    return null;
  }
}
