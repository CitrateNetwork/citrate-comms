import type { NextConfig } from "next";

/**
 * Static, request-independent security headers. The CSP carries a per-request
 * nonce and is applied in `src/proxy.ts` from `src/lib/security/csp.ts`
 * (script-src is `'nonce-…' 'strict-dynamic'`, never `'unsafe-inline'`). Pattern
 * ported from citrate-dataroom (SECREM-02 / FUA-EXPLORER-04).
 */
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=()" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
