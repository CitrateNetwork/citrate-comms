"use client";

/**
 * Audit — the sealed-ledger zone. A dark, read-only vault rendering the BLAKE3
 * hash-chained metadata log (who did what, when — never message content). "Verify
 * now" re-walks the chain and recomputes every hash. Append-only by construction.
 */
import { useState } from "react";
import { Icon } from "@/components/primitives";
import { SelectableText } from "@/components/primitives/SelectableText";
import styles from "./AuditScreen.module.css";

export interface UiAudit {
  seq: number;
  actorSub: string | null;
  event: string;
  target: string | null;
  ts: string;
  hash: string;
}
export interface Integrity {
  verified: boolean;
  recordCount: number;
  brokenAtSeq?: number;
}

export function AuditScreen({
  workspaceId,
  records,
  initialIntegrity,
  directory,
}: {
  workspaceId: string;
  records: UiAudit[];
  initialIntegrity: Integrity;
  directory: Record<string, string>;
}) {
  const [integrity, setIntegrity] = useState(initialIntegrity);
  const [verifying, setVerifying] = useState(false);

  async function verify() {
    setVerifying(true);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/audit/verify`, { method: "POST" });
      if (r.ok) {
        const { integrity: i } = (await r.json()) as { integrity: Integrity };
        setIntegrity(i);
      }
    } finally {
      setVerifying(false);
    }
  }

  function actor(sub: string | null): string {
    if (!sub) return "system";
    return directory[sub] ?? sub.slice(0, 10);
  }

  return (
    <div className={styles.sealed}>
      <header className={styles.head}>
        <div>
          <div className={styles.eyebrow}>Sealed ledger</div>
          <h1 className={styles.title}>Audit log</h1>
        </div>
        <button className={styles.verifyBtn} onClick={verify} disabled={verifying}>
          <Icon name="refresh" size={14} /> {verifying ? "Verifying…" : "Verify now"}
        </button>
      </header>

      <div className={styles.statusBar}>
        <span className={`${styles.dot} ${integrity.verified ? styles.ok : styles.bad}`} />
        {integrity.verified
          ? `Verified — ${integrity.recordCount} records, intact`
          : `Integrity broken at record #${integrity.brokenAtSeq}`}
      </div>

      <p className={styles.note}>
        A permanent, tamper-evident record of <strong>what happened</strong> — who joined, what was created.
        Never the contents of your messages.
      </p>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Event</th>
              <th>Actor</th>
              <th>Hash</th>
            </tr>
          </thead>
          <tbody>
            {records.length === 0 && (
              <tr>
                <td colSpan={5} className={styles.empty}>
                  No events yet.
                </td>
              </tr>
            )}
            {records.map((r) => (
              <tr key={r.seq}>
                <td className={styles.seq}>{r.seq}</td>
                <td className={styles.time}>{new Date(r.ts).toLocaleString()}</td>
                <td className={styles.event}>{r.event.replace(/_/g, " ")}</td>
                <td>{actor(r.actorSub)}</td>
                <td>
                  <SelectableText style={{ color: "var(--sealed-fg-2)" }}>{`${r.hash.slice(0, 16)}…`}</SelectableText>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className={styles.footer}>Append-only. Nothing here can be edited or deleted — by anyone, ever.</div>
    </div>
  );
}
