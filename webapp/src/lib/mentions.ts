/**
 * MEN — @-mention parsing + handles, shared by the composer (autocomplete) and the server
 * (deciding which agents to call into a channel / which members to ping). Dependency-free
 * and pure so it unit-tests cleanly and runs identically on client and server.
 *
 * A handle is the normalized, space-free token used after `@` (e.g. "Executive Assistant"
 * → "executive-assistant"). Matching is handle-based so multi-word names work.
 */

export type MentionKind = "member" | "agent";

export interface Mentionable {
  id: string;
  name: string;
  sub: string; // member sub (humans) or agent member sub (agents)
  kind: MentionKind;
}

/** Normalize a display name to a space-free @-handle. */
export function toHandle(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** Decorate candidates with their handle (stable sort: agents first, then by name). */
export function withHandles(candidates: Omit<Mentionable, never>[]): (Mentionable & { handle: string })[] {
  return candidates
    .map((c) => ({ ...c, handle: toHandle(c.name) }))
    .filter((c) => c.handle.length > 0)
    .sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === "agent" ? -1 : 1));
}

const MENTION_RE = /(^|[^a-zA-Z0-9_])@([a-z0-9][a-z0-9._-]*)/gi;

/** Extract the distinct @handles present in a body (lowercased, no leading @). */
export function extractHandles(body: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  MENTION_RE.lastIndex = 0;
  while ((m = MENTION_RE.exec(body))) out.add(m[2]!.toLowerCase().replace(/[._-]+$/g, ""));
  return [...out];
}

/**
 * Resolve which candidates a body mentions. Matches a handle exactly, or as the longest
 * candidate handle that is a prefix of the typed token (so "@executive-assistant" matches
 * even if the user kept typing). Returns unique candidates, agents and members separated.
 */
export function parseMentions(
  body: string,
  candidates: Mentionable[],
): { agents: Mentionable[]; members: Mentionable[]; all: Mentionable[] } {
  const handles = extractHandles(body);
  const withH = withHandles(candidates);
  const seen = new Set<string>();
  const all: Mentionable[] = [];
  for (const h of handles) {
    // exact first, else longest prefix match
    const exact = withH.find((c) => c.handle === h);
    const match = exact ?? withH.filter((c) => h.startsWith(c.handle)).sort((a, b) => b.handle.length - a.handle.length)[0];
    if (match && !seen.has(match.sub)) {
      seen.add(match.sub);
      all.push({ id: match.id, name: match.name, sub: match.sub, kind: match.kind });
    }
  }
  return {
    agents: all.filter((c) => c.kind === "agent"),
    members: all.filter((c) => c.kind === "member"),
    all,
  };
}

/** Filter+rank candidates for an autocomplete query (the text typed after `@`). */
export function filterMentionables(candidates: Mentionable[], query: string, limit = 8): (Mentionable & { handle: string })[] {
  const q = query.toLowerCase();
  const withH = withHandles(candidates);
  if (!q) return withH.slice(0, limit);
  return withH
    .filter((c) => c.handle.includes(q) || c.name.toLowerCase().includes(q))
    .sort((a, b) => {
      // prefix matches rank above substring matches
      const ap = a.handle.startsWith(q) ? 0 : 1;
      const bp = b.handle.startsWith(q) ? 0 : 1;
      return ap - bp || a.name.localeCompare(b.name);
    })
    .slice(0, limit);
}
