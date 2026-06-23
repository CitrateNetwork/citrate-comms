/**
 * Auth seam barrel. Server consumers import from here; the only identity checks in
 * the app are `verifySession` / `requireOwner` (server) and the `/auth/*` routes.
 */
export * from "./types";
export * from "./config";
export * from "./cookies";
export * from "./session";
