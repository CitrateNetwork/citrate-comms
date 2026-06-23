/**
 * Transactional email (SMTP) for citrate-comms — currently the onboarding invite.
 * Shape follows citrate-dataroom/src/lib/email: env-driven SMTP, STARTTLS on 587 /
 * implicit TLS on 465, fail-soft for dev. Every send goes through `sendCompliant`,
 * which:
 *   - checks the suppression list first (never email an unsubscribed address),
 *   - adds the RFC 8058 one-click unsubscribe headers (List-Unsubscribe +
 *     List-Unsubscribe-Post) so Gmail/Outlook show a native one-click button, and
 *   - appends a visible, one-click unsubscribe footer link.
 * This keeps us CAN-SPAM / CASL compliant: one click, no traps, honored permanently.
 *
 * Env (set in Vercel; the operator owns the mailbox + password):
 *   SMTP_HOST    e.g. smtp.office365.com
 *   SMTP_PORT    587 (STARTTLS, default) or 465 (implicit TLS)
 *   SMTP_SECURE  "true" for 465; STARTTLS otherwise (default false)
 *   SMTP_USER    the authenticating mailbox (e.g. larry@citrate.ai)
 *   SMTP_PASS    the mailbox/app password  ← operator sets this
 *   EMAIL_FROM   From header, e.g. "Citrate Comms <larry@citrate.ai>"
 *                (falls back to SMTP_USER). NOTE: sending From a different address
 *                than SMTP_USER requires "Send As" rights on that mailbox in M365.
 *   APP_ORIGIN   absolute base for links (e.g. https://comms.citrate.ai)
 */
import nodemailer, { type Transporter } from "nodemailer";
import { unsubscribeToken } from "@/lib/security/crypto";
import { isSuppressed } from "./suppression";

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
}

/** Resolve SMTP config from env, or null when incomplete (host+user+pass required). */
export function smtpConfig(): SmtpConfig | null {
  const host = process.env.SMTP_HOST?.trim();
  const user = process.env.SMTP_USER?.trim();
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  const port = Number(process.env.SMTP_PORT || "587");
  const secure = process.env.SMTP_SECURE ? /^(1|true|yes)$/i.test(process.env.SMTP_SECURE) : port === 465;
  const from = process.env.EMAIL_FROM?.trim() || user;
  return { host, port, secure, user, pass, from };
}

export function emailConfigured(): boolean {
  return smtpConfig() !== null;
}

function appOrigin(): string {
  return (process.env.APP_ORIGIN || "https://citrate-comms-web.vercel.app").replace(/\/$/, "");
}

let cached: { transporter: Transporter; key: string } | null = null;
function transporter(cfg: SmtpConfig): Transporter {
  const key = `${cfg.host}:${cfg.port}:${cfg.secure}:${cfg.user}`;
  if (cached && cached.key === key) return cached.transporter;
  const t = nodemailer.createTransport({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth: { user: cfg.user, pass: cfg.pass },
  });
  cached = { transporter: t, key };
  return t;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export interface SendOutcome {
  sent: boolean;
  suppressed?: boolean; // recipient previously unsubscribed
  link?: string; // returned when SMTP is unconfigured (dev) so the admin can share manually
}

/**
 * The single send path. Suppression-checked, unsubscribe-headered, footer-appended.
 * Returns {suppressed:true} without sending if the address unsubscribed; returns
 * {sent:false, link} when SMTP is unconfigured (dev) so onboarding still works.
 */
async function sendCompliant(args: {
  to: string;
  subject: string;
  text: string;
  htmlBody: string;
  /** A primary link (e.g. the invite link) surfaced to the admin if SMTP is off. */
  primaryLink?: string;
}): Promise<SendOutcome> {
  const to = args.to.trim().toLowerCase();
  if (await isSuppressed(to)) return { sent: false, suppressed: true };

  const origin = appOrigin();
  const token = unsubscribeToken(to);
  const unsubPage = `${origin}/unsubscribe?u=${encodeURIComponent(token)}`;
  const unsubPost = `${origin}/api/unsubscribe?u=${encodeURIComponent(token)}`;

  const cfg = smtpConfig();
  if (!cfg) return { sent: false, link: args.primaryLink };

  const text = `${args.text}\n\n—\nDon't want these emails? Unsubscribe instantly: ${unsubPage}`;
  const html =
    `<div style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:480px;margin:0 auto;color:#1f221d">` +
    args.htmlBody +
    `<hr style="border:none;border-top:1px solid #e3e2dc;margin:24px 0" />` +
    `<p style="font-size:12px;color:#84867f">You received this because someone invited you to a Citrate ` +
    `workspace. <a href="${escapeHtml(unsubPage)}" style="color:#5a8205">Unsubscribe</a> — one click, instantly, ` +
    `no account needed.</p>` +
    `</div>`;

  try {
    await transporter(cfg).sendMail({
      from: cfg.from,
      to,
      subject: args.subject,
      text,
      html,
      headers: {
        // RFC 8058 one-click: mail clients render a native "Unsubscribe" button that
        // POSTs to the URL automatically. The mailto is the always-valid fallback.
        "List-Unsubscribe": `<mailto:larry@citrate.ai?subject=unsubscribe>, <${unsubPost}>`,
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
      },
    });
    return { sent: true };
  } catch (e) {
    // SMTP auth/transport failure (e.g. password not yet set, or a transient relay
    // error). Don't hard-fail onboarding — hand back the link so the admin can share
    // it manually, and log for diagnosis.
    console.error("[email] send failed; falling back to manual link:", (e as Error).message);
    return { sent: false, link: args.primaryLink };
  }
}

export interface InviteEmail {
  to: string;
  workspaceName: string;
  inviterName: string;
  role: string;
  link: string;
}

/** Send the workspace invite. Suppression-checked + one-click-unsubscribe compliant. */
export async function sendInviteEmail(msg: InviteEmail): Promise<SendOutcome> {
  const text = [
    `${msg.inviterName} invited you to join ${msg.workspaceName} on citrate-comms as ${msg.role}.`,
    ``,
    `Accept your invite:`,
    msg.link,
    ``,
    `This link expires in 7 days. If you weren't expecting this, you can ignore it.`,
  ].join("\n");

  const htmlBody =
    `<p style="font-size:14px"><strong>${escapeHtml(msg.inviterName)}</strong> invited you to join ` +
    `<strong>${escapeHtml(msg.workspaceName)}</strong> on citrate-comms as <strong>${escapeHtml(msg.role)}</strong>.</p>` +
    `<p style="margin:20px 0"><a href="${escapeHtml(msg.link)}" ` +
    `style="display:inline-block;background:#8ecc09;color:#0e0f0c;padding:12px 20px;border-radius:8px;` +
    `text-decoration:none;font-weight:600">Accept invite</a></p>` +
    `<p style="font-size:13px;color:#84867f">This link expires in 7 days. If you weren't expecting this, you can ignore it.</p>`;

  return sendCompliant({
    to: msg.to,
    subject: `Join ${msg.workspaceName} on citrate-comms`,
    text,
    htmlBody,
    primaryLink: msg.link,
  });
}
