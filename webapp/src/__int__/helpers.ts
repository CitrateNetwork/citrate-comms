/**
 * Shared helpers for the integration suite: unique per-run identities, a Request builder
 * that authenticates through the real mock-auth path, and member seeding.
 */
import { db } from "@/lib/db/client";
import { members } from "@/lib/db/schema";

export const run = Math.random().toString(36).slice(2, 8);
export const who = (n: string) => `it${run}${n}`;
export const sub = (n: string) => `dev:${who(n)}`;

export const req = (u: string, n: string | null, init: RequestInit = {}) =>
  new Request(`http://localhost${u}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(n ? { "x-citrate-dev-address": who(n) } : {}),
      ...((init.headers as Record<string, string>) ?? {}),
    },
  });

export const P = <T extends Record<string, string>>(o: T) => ({ params: Promise.resolve(o) });

export async function addMember(ws: string, n: string, role: string) {
  await db().insert(members).values({ workspaceId: ws, sub: sub(n), role, status: "active", displayName: n, isAgent: role === "Agent" });
}

export const mcpCall = (name: string, args: Record<string, unknown>, id: number | string = 1) =>
  JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
