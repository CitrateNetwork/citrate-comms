"use client";

/** Accept-invite action — binds the signed-in identity to the workspace at the
 *  granted role, then routes into it. Works regardless of which Citrate account
 *  (email / Google / wallet / passkey) you're signed in with — the invite link is
 *  the credential. Only an invalid/expired/used link fails. */
import { useState } from "react";
import { useRouter } from "next/navigation";
import styles from "./join.module.css";

const REASONS: Record<string, string> = {
  invalid: "This invite link is no longer valid — it may have expired or already been used. Ask an admin to send a new one.",
  rate_limited: "Too many attempts — please wait a moment and try again.",
};

export function AcceptInvite({ token }: { token: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/join", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const data = (await r.json().catch(() => ({}))) as { ok?: boolean; slug?: string; error?: string };
      if (r.ok && data.ok && data.slug) {
        router.push(`/w/${data.slug}/comms`);
        return;
      }
      setError(REASONS[data.error ?? ""] ?? "Couldn't accept the invite. Please try again.");
    } catch {
      setError("Network error — please retry.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {error && <div className={styles.error}>{error}</div>}
      <button className="btn btn-primary" onClick={accept} disabled={busy}>
        {busy ? "Joining…" : "Accept & join"}
      </button>
    </>
  );
}
