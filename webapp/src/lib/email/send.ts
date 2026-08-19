/**
 * Transactional email for citrate-comms — the onboarding invite.
 *
 * Two transports, tried in order; the first one configured wins:
 *   1. Resend (preferred)  — set RESEND_API_KEY. HTTPS API, no SMTP AUTH to keep
 *      alive, DKIM/SPF/DMARC handled by verifying the sending domain in Resend.
 *   2. SMTP (legacy)       — set SMTP_HOST/SMTP_USER/SMTP_PASS. Kept as a fallback;
 *      note Microsoft 365 is retiring Basic Auth for SMTP client submission, so this
 *      path is fragile and should not be relied on long-term.
 * If NEITHER is configured (dev), sends fail soft: the API hands back the invite link
 * so the admin can share it manually.
 *
 * Every send goes through `sendCompliant`, which — regardless of transport:
 *   - checks the suppression list first (never email an unsubscribed address),
 *   - adds the RFC 8058 one-click unsubscribe headers (List-Unsubscribe +
 *     List-Unsubscribe-Post) so Gmail/Outlook show a native one-click button, and
 *   - appends a visible, one-click unsubscribe footer link.
 * This keeps us CAN-SPAM / CASL compliant: one click, no traps, honored permanently.
 *
 * Env (set in Vercel):
 *   RESEND_API_KEY  re_… API key from resend.com  ← preferred; set this
 *   EMAIL_FROM      From header, e.g. "Citrate Comms <invites@citrate.ai>". The domain
 *                   (citrate.ai) must be verified in Resend. Falls back to SMTP_USER,
 *                   then to "Citrate Comms <onboarding@resend.dev>" for first-run tests.
 *   APP_ORIGIN      absolute base for links (e.g. https://communications.citrate.ai)
 *   -- legacy SMTP fallback (only used when RESEND_API_KEY is unset) --
 *   SMTP_HOST       e.g. smtp.office365.com
 *   SMTP_PORT       587 (STARTTLS, default) or 465 (implicit TLS)
 *   SMTP_SECURE     "true" for 465; STARTTLS otherwise (default false)
 *   SMTP_USER       the authenticating mailbox (e.g. larry@citrate.ai)
 *   SMTP_PASS       the mailbox/app password
 */
import nodemailer, { type Transporter } from "nodemailer";
import { Resend } from "resend";
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

/** Resolve the From header, shared by both transports. */
function fromHeader(fallback?: string): string {
  return process.env.EMAIL_FROM?.trim() || fallback || "Citrate Comms <onboarding@resend.dev>";
}

/** Resolve Resend config from env, or null when RESEND_API_KEY is unset. */
export function resendConfig(): { apiKey: string; from: string } | null {
  const apiKey = process.env.RESEND_API_KEY?.trim();
  if (!apiKey) return null;
  return { apiKey, from: fromHeader() };
}

/** Resolve SMTP config from env, or null when incomplete (host+user+pass required). */
export function smtpConfig(): SmtpConfig | null {
  const host = process.env.SMTP_HOST?.trim();
  const user = process.env.SMTP_USER?.trim();
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  const port = Number(process.env.SMTP_PORT || "587");
  const secure = process.env.SMTP_SECURE ? /^(1|true|yes)$/i.test(process.env.SMTP_SECURE) : port === 465;
  const from = fromHeader(user);
  return { host, port, secure, user, pass, from };
}

/** True when at least one transport (Resend preferred, SMTP legacy) is configured. */
export function emailConfigured(): boolean {
  return resendConfig() !== null || smtpConfig() !== null;
}

/** Which transport a live send would use — for diagnostics/health surfaces. */
export function emailTransport(): "resend" | "smtp" | "none" {
  if (resendConfig()) return "resend";
  if (smtpConfig()) return "smtp";
  return "none";
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

let cachedResend: { client: Resend; key: string } | null = null;
function resendClient(apiKey: string): Resend {
  if (cachedResend && cachedResend.key === apiKey) return cachedResend.client;
  const client = new Resend(apiKey);
  cachedResend = { client, key: apiKey };
  return client;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export interface SendOutcome {
  sent: boolean;
  suppressed?: boolean; // recipient previously unsubscribed
  link?: string; // returned when no transport is configured (dev) so the admin can share manually
  transport?: "resend" | "smtp"; // which transport delivered (set only when sent)
}

/**
 * The single send path. Suppression-checked, unsubscribe-headered, footer-appended.
 * Dispatches to Resend (preferred) then SMTP (legacy). Returns {suppressed:true}
 * without sending if the address unsubscribed; returns {sent:false, link} when no
 * transport is configured (dev) so onboarding still works.
 */
async function sendCompliant(args: {
  to: string;
  subject: string;
  text: string;
  htmlBody: string;
  /** A primary link (e.g. the invite link) surfaced to the admin if no transport is set. */
  primaryLink?: string;
}): Promise<SendOutcome> {
  const to = args.to.trim().toLowerCase();
  if (await isSuppressed(to)) return { sent: false, suppressed: true };

  const origin = appOrigin();
  const token = unsubscribeToken(to);
  const unsubPage = `${origin}/unsubscribe?u=${encodeURIComponent(token)}`;
  const unsubPost = `${origin}/api/unsubscribe?u=${encodeURIComponent(token)}`;

  const resendCfg = resendConfig();
  const smtpCfg = smtpConfig();
  if (!resendCfg && !smtpCfg) return { sent: false, link: args.primaryLink };

  const text = `${args.text}\n\n—\nDon't want these emails? Unsubscribe instantly: ${unsubPage}`;
  const html =
    `<div style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:480px;margin:0 auto;color:#1f221d">` +
    args.htmlBody +
    `<hr style="border:none;border-top:1px solid #e3e2dc;margin:24px 0" />` +
    `<p style="font-size:12px;color:#84867f">You received this because someone invited you to a Citrate ` +
    `workspace. <a href="${escapeHtml(unsubPage)}" style="color:#5a8205">Unsubscribe</a> — one click, instantly, ` +
    `no account needed.</p>` +
    `</div>`;

  // RFC 8058 one-click headers — identical across transports. Mail clients render a
  // native "Unsubscribe" button that POSTs to the URL automatically; the mailto is the
  // always-valid fallback.
  const listUnsubHeaders: Record<string, string> = {
    "List-Unsubscribe": `<mailto:larry@citrate.ai?subject=unsubscribe>, <${unsubPost}>`,
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
  };

  // 1) Resend (preferred). HTTPS API — no SMTP AUTH dependency.
  if (resendCfg) {
    try {
      const { data, error } = await resendClient(resendCfg.apiKey).emails.send({
        from: resendCfg.from,
        to,
        subject: args.subject,
        text,
        html,
        headers: listUnsubHeaders,
      });
      if (error) throw new Error(`${error.name}: ${error.message}`);
      if (!data?.id) throw new Error("resend returned no message id");
      return { sent: true, transport: "resend" };
    } catch (e) {
      // Resend rejected (bad key, unverified domain, rate limit). Fall through to SMTP
      // if configured, otherwise hand back the manual link.
      console.error("[email] resend send failed:", (e as Error).message);
      if (!smtpCfg) return { sent: false, link: args.primaryLink };
    }
  }

  // 2) SMTP (legacy fallback).
  if (smtpCfg) {
    try {
      await transporter(smtpCfg).sendMail({
        from: smtpCfg.from,
        to,
        subject: args.subject,
        text,
        html,
        headers: listUnsubHeaders,
      });
      return { sent: true, transport: "smtp" };
    } catch (e) {
      // SMTP auth/transport failure (e.g. password not set, or M365 SMTP AUTH disabled).
      // Don't hard-fail onboarding — hand back the link so the admin can share it, and log.
      console.error("[email] smtp send failed; falling back to manual link:", (e as Error).message);
      return { sent: false, link: args.primaryLink };
    }
  }

  return { sent: false, link: args.primaryLink };
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

export interface CalendarEmail {
  to: string;
  kind: "invite" | "update" | "cancel" | "reminder" | "deadline";
  title: string;
  whenText: string; // human, viewer/recipient-timezone-aware, e.g. "Mon, Aug 25 · 2:00–2:30 PM PDT"
  organizerName: string;
  workspaceName: string;
  location?: string | null;
  notes?: string | null;
  raciRole?: "R" | "A" | "C" | "I" | null;
  link: string; // deep link to the calendar / event
}

const CAL_VERB: Record<CalendarEmail["kind"], string> = {
  invite: "invited you to",
  update: "updated",
  cancel: "cancelled",
  reminder: "Reminder:",
  deadline: "assigned you a deadline:",
};
const RACI_WORD: Record<"R" | "A" | "C" | "I", string> = { R: "Responsible", A: "Accountable", C: "Consulted", I: "Informed" };

/** Send a calendar booking/deadline/reminder email. Suppression-checked + one-click unsubscribe. */
export async function sendCalendarEmail(msg: CalendarEmail): Promise<SendOutcome> {
  const isDeadline = msg.kind === "deadline";
  const lead =
    msg.kind === "reminder"
      ? `Reminder — ${msg.title}`
      : msg.kind === "cancel"
        ? `${msg.organizerName} cancelled “${msg.title}”`
        : isDeadline
          ? `${msg.organizerName} assigned you a deadline: ${msg.title}`
          : `${msg.organizerName} ${CAL_VERB[msg.kind]} ${msg.kind === "update" ? `“${msg.title}”` : `“${msg.title}”`}`;

  const raciLine = msg.raciRole ? `Your role: ${RACI_WORD[msg.raciRole]} (${msg.raciRole})` : "";
  const text = [
    lead,
    ``,
    `When: ${msg.whenText}`,
    msg.location ? `Where: ${msg.location}` : "",
    raciLine,
    msg.notes ? `\n${msg.notes}` : "",
    ``,
    `Open in ${msg.workspaceName}: ${msg.link}`,
  ]
    .filter((l) => l !== "")
    .join("\n");

  const accent = isDeadline || msg.kind === "cancel" ? "#c2410c" : "#5a8205";
  const htmlBody =
    `<p style="font-size:15px;font-weight:600;color:#1f221d">${escapeHtml(lead)}</p>` +
    `<table style="font-size:14px;color:#1f221d;border-collapse:collapse">` +
    `<tr><td style="padding:2px 12px 2px 0;color:#84867f">When</td><td style="padding:2px 0"><strong>${escapeHtml(msg.whenText)}</strong></td></tr>` +
    (msg.location ? `<tr><td style="padding:2px 12px 2px 0;color:#84867f">Where</td><td style="padding:2px 0">${escapeHtml(msg.location)}</td></tr>` : "") +
    (msg.raciRole ? `<tr><td style="padding:2px 12px 2px 0;color:#84867f">Your role</td><td style="padding:2px 0"><strong style="color:${accent}">${RACI_WORD[msg.raciRole]} (${msg.raciRole})</strong></td></tr>` : "") +
    `</table>` +
    (msg.notes ? `<p style="font-size:13px;color:#4a4d46;margin-top:12px;white-space:pre-wrap">${escapeHtml(msg.notes)}</p>` : "") +
    `<p style="margin:20px 0"><a href="${escapeHtml(msg.link)}" ` +
    `style="display:inline-block;background:${accent};color:#fff;padding:12px 20px;border-radius:8px;` +
    `text-decoration:none;font-weight:600">Open calendar</a></p>`;

  const subjectPrefix = msg.kind === "cancel" ? "Cancelled: " : msg.kind === "reminder" ? "Reminder: " : isDeadline ? "Deadline: " : "";
  return sendCompliant({
    to: msg.to,
    subject: `${subjectPrefix}${msg.title} — ${msg.workspaceName}`,
    text,
    htmlBody,
    primaryLink: msg.link,
  });
}
