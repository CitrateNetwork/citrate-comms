"use client";

/**
 * Read-only, click-to-copy mono text — wallet addresses, message ids, audit hashes.
 * Mirrors the native SelectableText primitive (Geist Mono, de-emphasized).
 */
import { useState, type CSSProperties } from "react";
import { Icon } from "./icons";

export function SelectableText({ children, style }: { children: string; style?: CSSProperties }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(children);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable — selection still works */
    }
  };
  return (
    <span className="mono sel-text" onClick={copy} title="Click to copy" style={{ cursor: "pointer", ...style }}>
      {children}
      <Icon name={copied ? "check" : "copy"} size={12} style={{ marginLeft: 4, opacity: 0.6 }} />
    </span>
  );
}
