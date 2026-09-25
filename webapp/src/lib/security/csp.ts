/**
 * Content-Security-Policy builder (PBA-L3c-008). Ported from citrate-dataroom /
 * citrate-explorer (SECREM-02 WP 7.1). Built per request in src/proxy.ts with a fresh
 * nonce, so script-src needs neither 'unsafe-inline' nor 'unsafe-eval':
 *  - `'nonce-<random>'` — Next's own framework scripts (stamped during SSR).
 *  - `'strict-dynamic'` — chunks loaded BY nonce'd scripts are trusted transitively
 *    (the lazy mermaid / vega-embed bundles).
 *  - no 'unsafe-eval': chat charts run vega with the AST interpreter (`ast: true`), and
 *    mermaid renders without eval.
 *
 * This is the second layer behind the markdown sanitizer for LLM output rendered as
 * mermaid SVG / vega charts (components/agents/Markdown.tsx).
 *
 * Documented relaxation: `style-src 'unsafe-inline'` — the design system and mermaid's
 * generated SVG use inline styles; nonces can't cover style attributes. Style injection
 * is not script execution. img/media allow https: for Blob-stored attachments (served
 * via the access-controlled proxy's redirect).
 */
function originOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** Build the full CSP for one request. `nonce` MUST be unique per request. */
export function buildCsp(nonce: string, env: Record<string, string | undefined> = process.env): string {
  const connect = new Set<string>(["'self'"]);
  const issuer = originOf(env.NEXT_PUBLIC_OIDC_ISSUER);
  if (issuer) connect.add(issuer);
  const formAction = new Set<string>(["'self'"]);
  if (issuer) formAction.add(issuer);

  const directives: Record<string, string> = {
    "default-src": "'self'",
    "script-src": `'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data: blob: https:",
    "media-src": "'self' blob: https:",
    "font-src": "'self' data:",
    "connect-src": [...connect].join(" "),
    "frame-src": "'none'",
    "worker-src": "'self' blob:",
    "manifest-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'self'",
    "form-action": [...formAction].join(" "),
    "frame-ancestors": "'none'",
  };
  if (env.NODE_ENV === "production") directives["upgrade-insecure-requests"] = "";

  return Object.entries(directives)
    .map(([k, v]) => (v ? `${k} ${v}` : k))
    .join("; ");
}

/** A fresh base64 nonce (128 bits). */
export function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}
