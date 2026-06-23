import type { Metadata, Viewport } from "next";
import "@/styles/tokens.css";
import "@/styles/app.css";

export const metadata: Metadata = {
  title: "citrate-comms",
  description: "End-to-end-encrypted, agentic team workspace — Comms · CRM · Projects.",
};

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
