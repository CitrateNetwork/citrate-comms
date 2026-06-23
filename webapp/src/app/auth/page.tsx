import styles from "./auth.module.css";

/**
 * Sign-in front door (design brief §6-A1). One primary action that begins the
 * Authorization Code + PKCE flow against the citrate-identity spine — the
 * authority's own interaction page offers email / passkey / Google / wallet, with
 * email + passkey + Google as the primary team onramp.
 *
 * The honest trust-boundary note is here from the first screen: this web client is
 * team-trusted (the server can read content), distinct from the native app's
 * server-blind MLS posture.
 */
const ERRORS: Record<string, string> = {
  invalid_state: "Your sign-in session expired. Please try again.",
  token_exchange_failed: "The authority rejected the sign-in. Please try again.",
  token_exchange_error: "Couldn't reach the authority. Check your connection and retry.",
  no_id_token: "Sign-in did not complete. Please try again.",
  no_subject: "The identity token was missing a subject. Contact your admin.",
};

export default async function SignIn({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; returnTo?: string }>;
}) {
  const { error, returnTo } = await searchParams;
  const startHref = `/auth/start${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ""}`;

  return (
    <main className={styles.screen}>
      <section className={styles.brand}>
        <div className={styles.mark}>◐ citrate-comms</div>
        <div className={styles.tagline}>Your team&apos;s private workspace — encrypted, agentic, yours.</div>
        <div className={styles.brandFoot}>Comms · CRM · Projects — one encrypted workspace</div>
      </section>

      <section className={styles.panel}>
        <div className={styles.card}>
          <div className={styles.eyebrow}>Welcome</div>
          <h1 className={styles.title}>Sign in</h1>
          <p className={styles.sub}>
            Continue with your Citrate account — email, passkey, Google, or your wallet.
          </p>

          {error && <div className={styles.error}>{ERRORS[error] ?? "Sign-in failed. Please try again."}</div>}

          <form action={startHref} method="get">
            {returnTo && <input type="hidden" name="returnTo" value={returnTo} />}
            <button type="submit" className={styles.signin}>
              Sign in to continue
            </button>
          </form>

          <div className={styles.methods}>Email · Passkey · Google · Citrate wallet</div>
          <div className={styles.footnote}>End-to-end encrypted spine · self-hosted</div>

          <div className={styles.trust}>
            <strong>Web · team-trusted.</strong> This web client stores your messages and records
            encrypted at rest, but the server <em>can</em> read content to deliver it across devices.
            That is different from the native app, whose relay is <em>server-blind</em> (it can never
            read your messages). Both are end-to-end inside your team.
          </div>
        </div>
      </section>
    </main>
  );
}
