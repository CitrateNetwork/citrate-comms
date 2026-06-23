"use client";

/**
 * HITL approvals inbox (COMMS-CRM-DEPTH D3). Agent-proposed CRM writes land here for a
 * human to approve (apply) or reject. The summary is derived server-side from the
 * decrypted action so the approver sees exactly what they're committing.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Btn, SurfBadge } from "@/components/primitives";
import s from "@/components/common/screen.module.css";
import styles from "./ApprovalsInbox.module.css";

export interface UiApproval {
  id: string;
  tool: string;
  risk: "low" | "medium" | "high";
  requestedBySub: string;
  createdAt: string;
  summary: string;
}

export function ApprovalsInbox({ workspaceId, approvals }: { workspaceId: string; approvals: UiApproval[] }) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);

  async function decide(approvalId: string, decision: "approved" | "rejected") {
    setBusy(approvalId);
    await fetch(`/api/workspaces/${workspaceId}/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ approvalId, decision }),
    });
    setBusy(null);
    router.refresh();
  }

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <div className={s.eyebrow}>Workspace</div>
          <h1 className={s.title}>Approvals</h1>
        </div>
      </header>
      <p className={styles.note}>
        When an agent proposes a CRM change, it’s queued here — nothing is applied until a human approves.
        Every decision is audited.
      </p>

      {approvals.length === 0 ? (
        <div className={s.empty}>No pending approvals. Agent-proposed changes will appear here.</div>
      ) : (
        <div className={styles.list}>
          {approvals.map((a) => (
            <div key={a.id} className={styles.row}>
              <div className={styles.rowMain}>
                <div className={styles.rowTop}>
                  <span className={styles.tool}>{a.tool}</span>
                  <SurfBadge variant={a.risk === "high" ? "agent" : "outline"}>{a.risk} risk</SurfBadge>
                  <span className={styles.when}>{new Date(a.createdAt).toLocaleString()}</span>
                </div>
                <div className={styles.summary}>{a.summary}</div>
              </div>
              <div className={styles.actions}>
                <Btn variant="quiet" size="sm" onClick={() => decide(a.id, "rejected")} disabled={busy === a.id}>
                  Reject
                </Btn>
                <Btn variant="primary" size="sm" onClick={() => decide(a.id, "approved")} disabled={busy === a.id}>
                  {busy === a.id ? "…" : "Approve"}
                </Btn>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
