/**
 * Email suppression list (CAN-SPAM / CASL). Global, permanent-until-reopt. Every
 * send checks `isSuppressed` first; `suppress` is idempotent (re-unsubscribing is a
 * no-op). Honoring an unsubscribe is mandatory.
 */
import { eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { emailSuppression } from "@/lib/db/schema";

/** True if this address has unsubscribed and must not be emailed. */
export async function isSuppressed(email: string): Promise<boolean> {
  const e = email.trim().toLowerCase();
  const [row] = await db().select({ email: emailSuppression.email }).from(emailSuppression).where(eq(emailSuppression.email, e)).limit(1);
  return Boolean(row);
}

/** Add an address to the suppression list (idempotent). */
export async function suppress(email: string, reason: string): Promise<void> {
  const e = email.trim().toLowerCase();
  await db().insert(emailSuppression).values({ email: e, reason }).onConflictDoNothing();
}
