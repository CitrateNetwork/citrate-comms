"use client";

/**
 * Members & onboarding screen. Owners/Admins invite by email (email-primary),
 * change roles (anti-escalation enforced server-side AND reflected here), and
 * offboard. The offboard confirm states the real, honest semantics (forward-only,
 * not a remote wipe). Read-only for Members/Partners/Guests.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Avatar, Btn, Icon, RoleGlyph, SurfBadge } from "@/components/primitives";
import { SelectableText } from "@/components/primitives/SelectableText";
import { canGrant, type Role } from "@/lib/rbac/matrix";
import styles from "./MembersScreen.module.css";

export interface UiMember {
  sub: string;
  displayName: string;
  walletAddress: string | null;
  email: string | null;
  role: Role;
  status: string;
  isAgent: boolean;
  kycStatus: string | null;
}

export interface PendingInvite {
  email: string;
  role: Role;
  expiresAt: string;
}

interface Props {
  workspaceId: string;
  myRole: Role;
  mySub: string;
  canManage: boolean;
  members: UiMember[];
  pending: PendingInvite[];
}

const GRANTABLE: Role[] = ["Admin", "Member", "Partner", "Guest"];

export function MembersScreen({ workspaceId, myRole, mySub, canManage, members, pending }: Props) {
  const router = useRouter();
  const [inviteOpen, setInviteOpen] = useState(false);
  const [offboardTarget, setOffboardTarget] = useState<UiMember | null>(null);

  const active = members.filter((m) => m.status !== "offboarded");

  return (
    <div className={styles.wrap}>
      <header className={styles.head}>
        <div>
          <div className={styles.eyebrow}>Workspace</div>
          <h1 className={styles.title}>Members</h1>
        </div>
        {canManage && (
          <Btn variant="primary" icon="plus" onClick={() => setInviteOpen(true)}>
            Invite by email
          </Btn>
        )}
      </header>

      {pending.length > 0 && (
        <section className={styles.pending}>
          <div className={styles.sectionLabel}>Pending invites</div>
          {pending.map((p) => (
            <div key={p.email} className={styles.pendingRow}>
              <span className={styles.pendingEmail}>{p.email}</span>
              <RoleGlyph role={p.role} />
              <span className={styles.pendingMeta}>expires {new Date(p.expiresAt).toLocaleDateString()}</span>
            </div>
          ))}
        </section>
      )}

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Member</th>
              <th>Address</th>
              <th>Role</th>
              <th>Status</th>
              {canManage && <th />}
            </tr>
          </thead>
          <tbody>
            {active.map((m) => {
              const manageable = canManage && m.sub !== mySub && m.role !== "Owner" && canGrant(myRole, m.role);
              return (
                <tr key={m.sub}>
                  <td>
                    <div className={styles.memberCell}>
                      <Avatar name={m.displayName} size="sm" isAgent={m.isAgent} />
                      <div>
                        <div className={styles.name}>
                          {m.displayName}
                          {m.isAgent && <SurfBadge variant="agent">AGENT</SurfBadge>}
                          {m.sub === mySub && <span className={styles.you}>you</span>}
                        </div>
                        {m.email && <div className={styles.email}>{m.email}</div>}
                      </div>
                    </div>
                  </td>
                  <td>{m.walletAddress ? <SelectableText>{m.walletAddress}</SelectableText> : <span className={styles.dim}>—</span>}</td>
                  <td>
                    {manageable ? (
                      <RoleSelect
                        workspaceId={workspaceId}
                        sub={m.sub}
                        current={m.role}
                        onChanged={() => router.refresh()}
                      />
                    ) : (
                      <span className={styles.roleStatic}>
                        <RoleGlyph role={m.role} /> {m.role}
                      </span>
                    )}
                  </td>
                  <td>
                    <span className={`${styles.status} ${styles[`st_${m.status}`] ?? ""}`}>{m.status}</span>
                  </td>
                  {canManage && (
                    <td className={styles.actions}>
                      {manageable && (
                        <button className={styles.offboardBtn} onClick={() => setOffboardTarget(m)}>
                          Offboard
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {inviteOpen && (
        <InviteDialog workspaceId={workspaceId} onClose={() => setInviteOpen(false)} onDone={() => router.refresh()} />
      )}
      {offboardTarget && (
        <OffboardDialog
          workspaceId={workspaceId}
          member={offboardTarget}
          onClose={() => setOffboardTarget(null)}
          onDone={() => {
            setOffboardTarget(null);
            router.refresh();
          }}
        />
      )}
    </div>
  );
}

function RoleSelect({
  workspaceId,
  sub,
  current,
  onChanged,
}: {
  workspaceId: string;
  sub: string;
  current: Role;
  onChanged: () => void;
}) {
  const [role, setRole] = useState<Role>(current);
  const [busy, setBusy] = useState(false);
  async function change(next: Role) {
    setBusy(true);
    setRole(next);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/members`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sub, role: next }),
      });
      if (r.ok) onChanged();
      else setRole(current);
    } catch {
      setRole(current);
    } finally {
      setBusy(false);
    }
  }
  return (
    <select className={styles.roleSelect} value={role} disabled={busy} onChange={(e) => change(e.target.value as Role)}>
      {GRANTABLE.map((r) => (
        <option key={r} value={r}>
          {r}
        </option>
      ))}
    </select>
  );
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface InviteResult {
  email: string;
  emailSent: boolean;
  suppressed: boolean;
  link?: string;
}

function InviteDialog({
  workspaceId,
  onClose,
  onDone,
}: {
  workspaceId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [emails, setEmails] = useState<string[]>([]);
  const [input, setInput] = useState("");
  const [role, setRole] = useState<Role>("Member");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<InviteResult[] | null>(null);

  /** Add valid, de-duped emails from a blob (commas / tabs / spaces / newlines). */
  function addEmails(text: string) {
    const parts = text.split(/[\s,;]+/).map((p) => p.trim().toLowerCase()).filter(Boolean);
    if (parts.length === 0) return;
    setEmails((prev) => {
      const seen = new Set(prev);
      const next = [...prev];
      let bad = 0;
      for (const p of parts) {
        if (!EMAIL_RE.test(p)) { bad++; continue; }
        if (!seen.has(p)) { seen.add(p); next.push(p); }
      }
      setError(bad > 0 ? `${bad} entr${bad === 1 ? "y was" : "ies were"} not a valid email and ${bad === 1 ? "was" : "were"} skipped.` : null);
      return next;
    });
  }
  function commitInput() {
    if (input.trim()) addEmails(input);
    setInput("");
  }
  function removeEmail(e: string) {
    setEmails((prev) => prev.filter((x) => x !== e));
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === "Tab" || e.key === "," || e.key === ";") {
      if (input.trim()) { e.preventDefault(); commitInput(); }
    } else if (e.key === "Backspace" && input === "" && emails.length > 0) {
      removeEmail(emails[emails.length - 1]!);
    }
  }

  async function send() {
    if (busy) return;
    // Fold any half-typed address in before sending.
    const pending = input.trim().toLowerCase();
    const all = Array.from(new Set([...emails, ...(pending && EMAIL_RE.test(pending) ? [pending] : [])]));
    if (all.length === 0) { setError("Add at least one email."); return; }
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/invites/batch`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ workspaceId, emails: all, role }),
      });
      const data = (await r.json().catch(() => ({}))) as { results?: InviteResult[]; error?: string };
      if (!r.ok) {
        setError(r.status === 429 ? "Too many invites — wait a moment." : r.status === 403 ? "You can't grant that role." : "Couldn't send the invites.");
        return;
      }
      setInput("");
      setResults(data.results ?? []);
    } catch {
      setError("Network error — please retry.");
    } finally {
      setBusy(false);
    }
  }

  const total = emails.length + (input.trim() && EMAIL_RE.test(input.trim().toLowerCase()) ? 1 : 0);

  return (
    <div className={styles.scrim} onClick={onClose}>
      <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={styles.dialogHead}>Invite teammates</div>
        {results ? (
          <div className={styles.manual}>
            <p className={styles.manualNote}>
              {results.filter((r) => r.emailSent).length} sent
              {results.some((r) => r.suppressed) && `, ${results.filter((r) => r.suppressed).length} suppressed (unsubscribed)`}
              {results.some((r) => !r.emailSent && r.link) && `, ${results.filter((r) => !r.emailSent && r.link).length} need a manual link`}.
            </p>
            <div className={styles.results}>
              {results.map((r) => (
                <div key={r.email} className={styles.resultRow}>
                  <span className={styles.resultEmail}>{r.email}</span>
                  {r.emailSent ? (
                    <span className={styles.ok}><Icon name="check" size={12} /> sent</span>
                  ) : r.suppressed ? (
                    <span className={styles.warn}>unsubscribed</span>
                  ) : r.link ? (
                    <SelectableText>{r.link}</SelectableText>
                  ) : (
                    <span className={styles.warn}>failed</span>
                  )}
                </div>
              ))}
            </div>
            <div className={styles.dialogFoot}>
              <Btn variant="quiet" type="button" onClick={() => { setResults(null); setEmails([]); }}>Invite more</Btn>
              <Btn variant="primary" onClick={() => { onDone(); onClose(); }}>Done</Btn>
            </div>
          </div>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); send(); }} className={styles.form}>
            <label className={styles.field}>
              <span className={styles.fieldLabel}>Emails — separate with comma, tab, or Enter; paste a list too</span>
              <div className={styles.chipField}>
                {emails.map((e) => (
                  <span key={e} className={styles.emailChip}>
                    {e}
                    <button type="button" className={styles.chipX} onClick={() => removeEmail(e)} aria-label={`Remove ${e}`}>
                      <Icon name="x" size={11} />
                    </button>
                  </span>
                ))}
                <input
                  className={styles.chipInput}
                  type="text"
                  inputMode="email"
                  placeholder={emails.length === 0 ? "teammate@company.com, another@company.com" : "add another…"}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={onKeyDown}
                  onBlur={commitInput}
                  onPaste={(e) => { e.preventDefault(); addEmails(e.clipboardData.getData("text")); }}
                  autoFocus
                />
              </div>
            </label>
            <label className={styles.field}>
              <span className={styles.fieldLabel}>Role (applies to everyone in this batch)</span>
              <select className={styles.input} value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {GRANTABLE.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            {error && <div className={styles.error}>{error}</div>}
            <div className={styles.dialogFoot}>
              <Btn variant="quiet" type="button" onClick={onClose}>
                Cancel
              </Btn>
              <Btn variant="primary" type="submit" disabled={busy || total === 0}>
                {busy ? "Sending…" : total > 1 ? `Send ${total} invites` : "Send invite"}
              </Btn>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function OffboardDialog({
  workspaceId,
  member,
  onClose,
  onDone,
}: {
  workspaceId: string;
  member: UiMember;
  onClose: () => void;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function offboard() {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/members`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sub: member.sub }),
      });
      if (r.ok) onDone();
      else setError("Couldn't offboard this member.");
    } catch {
      setError("Network error — please retry.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className={styles.scrim} onClick={onClose}>
      <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={styles.dialogHead}>Offboard {member.displayName}?</div>
        <div className={styles.honest}>
          {member.displayName} loses access to <strong>future</strong> messages and records right away. They keep
          what they already received — this isn&apos;t a remote wipe, and it can&apos;t be undone.
        </div>
        {error && <div className={styles.error}>{error}</div>}
        <div className={styles.dialogFoot}>
          <Btn variant="quiet" onClick={onClose}>
            Cancel
          </Btn>
          <Btn variant="danger-solid" onClick={offboard} disabled={busy}>
            {busy ? "Offboarding…" : "Offboard"}
          </Btn>
        </div>
      </div>
    </div>
  );
}
