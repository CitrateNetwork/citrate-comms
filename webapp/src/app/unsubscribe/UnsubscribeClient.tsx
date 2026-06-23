"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import styles from "./unsubscribe.module.css";

type State = "working" | "done" | "error";

export function UnsubscribeClient() {
  const params = useSearchParams();
  const token = params.get("u");
  const alreadyDone = params.get("done") === "1";
  const hadError = params.get("error") === "1";

  const [state, setState] = useState<State>(alreadyDone ? "done" : hadError ? "error" : "working");
  const [email, setEmail] = useState<string | null>(null);

  useEffect(() => {
    if (alreadyDone || hadError || !token) {
      if (!token && !alreadyDone) setState("error");
      return;
    }
    // One click from the email: process immediately on open. POSTed (not a GET
    // mutation), so email link-prefetchers won't trigger it.
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch("/api/unsubscribe", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (cancelled) return;
        if (r.ok) {
          const data = (await r.json()) as { email?: string };
          setEmail(data.email ?? null);
          setState("done");
        } else {
          setState("error");
        }
      } catch {
        if (!cancelled) setState("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token, alreadyDone, hadError]);

  if (state === "working") {
    return (
      <>
        <h1 className={styles.title}>Unsubscribing…</h1>
        <p className={styles.sub}>One moment.</p>
      </>
    );
  }
  if (state === "error") {
    return (
      <>
        <h1 className={styles.title}>This link isn&apos;t valid</h1>
        <p className={styles.sub}>
          The unsubscribe link may be malformed. If you keep receiving unwanted email, reply to it or contact{" "}
          <a href="mailto:larry@citrate.ai" className={styles.link}>larry@citrate.ai</a> and we&apos;ll remove you.
        </p>
      </>
    );
  }
  return (
    <>
      <h1 className={styles.title}>You&apos;re unsubscribed</h1>
      <p className={styles.sub}>
        {email ? <><strong>{email}</strong> has</> : "You have"} been removed from citrate-comms invitation
        emails. You won&apos;t receive any more. This took effect immediately.
      </p>
      <p className={styles.fine}>
        Changed your mind? Ask a workspace admin to invite you again, or email{" "}
        <a href="mailto:larry@citrate.ai" className={styles.link}>larry@citrate.ai</a>.
      </p>
    </>
  );
}
