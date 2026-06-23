import Link from "next/link";
import { serverSession } from "@/lib/auth/server";
import { lookupInvite } from "@/lib/domain/invites";
import { AcceptInvite } from "./AcceptInvite";
import styles from "./join.module.css";

/**
 * Invite landing (design brief §6-A3). Resolves the one-time token, then either
 * prompts sign-in (email/passkey/Google/wallet via the spine) or shows the accept
 * action with the workspace + role being granted. Email-primary onboarding.
 */
export const dynamic = "force-dynamic";

export default async function JoinPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const invite = await lookupInvite(token);

  if (!invite) {
    return (
      <main className={styles.screen}>
        <div className={styles.card}>
          <div className={styles.mark}>◐ citrate-comms</div>
          <h1 className={styles.title}>This invite isn&apos;t valid</h1>
          <p className={styles.sub}>The link may have expired, already been used, or been revoked. Ask your admin to send a new one.</p>
          <Link href="/auth" className="btn btn-ghost">Go to sign in</Link>
        </div>
      </main>
    );
  }

  const session = await serverSession();
  const authed = session.authenticated && Boolean(session.sub);

  return (
    <main className={styles.screen}>
      <div className={styles.card}>
        <div className={styles.mark}>◐ citrate-comms</div>
        <div className={styles.eyebrow}>You&apos;re invited</div>
        <h1 className={styles.title}>Join {invite.workspaceName}</h1>
        <p className={styles.sub}>
          You&apos;ve been invited to <strong>{invite.workspaceName}</strong> as{" "}
          <strong>{invite.role}</strong>
          {invite.role === "Partner" && " — an external, scoped role"}.
        </p>
        <div className={styles.metaRow}>
          <span className={styles.metaLabel}>Sent to</span>
          <span className={styles.metaVal}>{invite.email}</span>
        </div>

        {authed ? (
          <>
            <div className={styles.metaRow}>
              <span className={styles.metaLabel}>Joining as</span>
              <span className={styles.metaVal}>
                {session.email ??
                  (session.walletAddress
                    ? `${session.walletAddress.slice(0, 6)}…${session.walletAddress.slice(-4)}`
                    : "your Citrate account")}
              </span>
            </div>
            <AcceptInvite token={token} />
            <p className={styles.foot}>
              You&apos;ll join with the account you&apos;re signed in as — it doesn&apos;t need to match the
              address the invite was sent to.
            </p>
          </>
        ) : (
          <>
            <Link
              href={`/auth/start?returnTo=${encodeURIComponent(`/join/${token}`)}`}
              prefetch={false}
              className="btn btn-primary"
            >
              Sign in to accept
            </Link>
            <p className={styles.foot}>Continue with email, passkey, Google, or your Citrate wallet.</p>
          </>
        )}
      </div>
    </main>
  );
}
