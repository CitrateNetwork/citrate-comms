/**
 * Server-component session resolution — the CANONICAL way pages/layouts read the
 * session. Reads the id_token from `cookies()` (next/headers) rather than
 * reconstructing a synthetic Request from `headers()`, which did not reliably carry
 * the cookie and caused authenticated navigations to bounce to /auth.
 *
 * `cookies()` also reflects the token forwarded by proxy.ts (silent refresh), so a
 * just-refreshed session is seen within the same request.
 */
import { cookies } from "next/headers";
import { ID_COOKIE } from "./cookies";
import { resolveServerAuthMode, verifyOidcToken, verifyMockToken, sessionOwner } from "./session";
import type { AuthSession } from "./types";

/** The verified session for the current server request. */
export async function serverSession(): Promise<AuthSession> {
  const token = (await cookies()).get(ID_COOKIE)?.value ?? null;
  const mode = resolveServerAuthMode();
  if (mode === "oidc") return verifyOidcToken(token);
  if (mode === "mock-disabled") return { required: true, authenticated: false };
  return verifyMockToken(token, null);
}

/** The canonical owner key (OIDC sub) for the current request, or null. */
export async function serverOwner(): Promise<string | null> {
  return sessionOwner(await serverSession());
}
