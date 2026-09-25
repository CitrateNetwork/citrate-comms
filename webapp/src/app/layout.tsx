import type { Metadata, Viewport } from "next";
import "@/styles/tokens.css";
import "@/styles/app.css";

export const metadata: Metadata = {
  title: "citrate-comms",
  // The native app is server-blind (E2E); this DEPLOYED web tier is trusted-tier
  // (the server holds COMMS_ENC_KEY and decrypts to serve), as the in-product
  // Settings/auth copy states. Do not tag the web app "end-to-end-encrypted"
  // (CIT-COMMS-006 / CM2-B-A008).
  description: "Agentic team workspace — Comms · CRM · Projects. Encrypted at rest; server-blind E2E on the native app.",
};

// PBA-L3c-008: the CSP is nonce-based (src/proxy.ts); a statically prerendered page would
// ship framework <script> tags without the per-request nonce, so every page renders
// dynamically.
export const dynamic = "force-dynamic";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#f4f1ea",
};

/**
 * Root layout. The design system is driven by data-* attributes on <html>:
 * `data-density` (cinematic|compact), `data-accent`, `data-reduced-motion`,
 * `data-msg-style`, `data-agent-treat`. They default here and become real,
 * persisted user settings in the Appearance pane (P4). tokens.css + app.css are
 * carried verbatim from the native design package.
 */
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      data-density="cinematic"
      data-accent="green"
      data-msg-style="editorial"
      data-agent-treat="rule"
    >
      <body>{children}</body>
    </html>
  );
}
