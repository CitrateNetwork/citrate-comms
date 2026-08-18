/**
 * Transport-selection contract for invite email. Resend is preferred; SMTP is the
 * legacy fallback; with neither configured the caller gets a manual link (fail-soft).
 * These are pure env-driven resolvers — no network — so they lock the migration
 * without exercising a real provider.
 */
import { afterEach, describe, expect, it } from "vitest";
import { emailConfigured, emailTransport, resendConfig, smtpConfig } from "./send";

const EMAIL_ENV = ["RESEND_API_KEY", "EMAIL_FROM", "SMTP_HOST", "SMTP_PORT", "SMTP_SECURE", "SMTP_USER", "SMTP_PASS"] as const;

function clearEmailEnv() {
  for (const k of EMAIL_ENV) delete process.env[k];
}

afterEach(clearEmailEnv);

describe("email transport selection", () => {
  it("reports no transport when nothing is configured", () => {
    clearEmailEnv();
    expect(emailConfigured()).toBe(false);
    expect(emailTransport()).toBe("none");
    expect(resendConfig()).toBeNull();
    expect(smtpConfig()).toBeNull();
  });

  it("prefers Resend when RESEND_API_KEY is set", () => {
    clearEmailEnv();
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.EMAIL_FROM = "Citrate Comms <invites@citrate.ai>";
    expect(emailConfigured()).toBe(true);
    expect(emailTransport()).toBe("resend");
    expect(resendConfig()).toEqual({ apiKey: "re_test_key", from: "Citrate Comms <invites@citrate.ai>" });
  });

  it("prefers Resend even when SMTP is also configured", () => {
    clearEmailEnv();
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.SMTP_HOST = "smtp.office365.com";
    process.env.SMTP_USER = "larry@citrate.ai";
    process.env.SMTP_PASS = "secret";
    expect(emailTransport()).toBe("resend");
  });

  it("falls back to SMTP when only SMTP is configured", () => {
    clearEmailEnv();
    process.env.SMTP_HOST = "smtp.office365.com";
    process.env.SMTP_USER = "larry@citrate.ai";
    process.env.SMTP_PASS = "secret";
    expect(emailConfigured()).toBe(true);
    expect(emailTransport()).toBe("smtp");
    expect(smtpConfig()).toMatchObject({ host: "smtp.office365.com", port: 587, secure: false, from: "larry@citrate.ai" });
  });

  it("treats partial SMTP config (no password) as unconfigured", () => {
    clearEmailEnv();
    process.env.SMTP_HOST = "smtp.office365.com";
    process.env.SMTP_USER = "larry@citrate.ai";
    // SMTP_PASS intentionally unset
    expect(smtpConfig()).toBeNull();
    expect(emailTransport()).toBe("none");
  });

  it("uses implicit TLS defaults for port 465", () => {
    clearEmailEnv();
    process.env.SMTP_HOST = "smtp.example.com";
    process.env.SMTP_USER = "u@example.com";
    process.env.SMTP_PASS = "secret";
    process.env.SMTP_PORT = "465";
    expect(smtpConfig()).toMatchObject({ port: 465, secure: true });
  });
});
