import { Suspense } from "react";
import { UnsubscribeClient } from "./UnsubscribeClient";
import styles from "./unsubscribe.module.css";

/**
 * Unsubscribe confirmation page (comms.citrate.ai/unsubscribe). One click from the
 * email: when arriving with `?u=<token>` it auto-submits the unsubscribe on load
 * (no button to hunt for, no trap) and confirms. `?done=1` shows the confirmed state
 * for the GET-link path. Public, no auth.
 */
export const dynamic = "force-dynamic";

export default function UnsubscribePage() {
  return (
    <main className={styles.screen}>
      <div className={styles.card}>
        <div className={styles.mark}>◐ citrate-comms</div>
        <Suspense fallback={<p className={styles.sub}>Loading…</p>}>
          <UnsubscribeClient />
        </Suspense>
      </div>
    </main>
  );
}
