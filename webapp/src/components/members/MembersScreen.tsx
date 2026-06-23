"use client";

/**
 * Members & onboarding screen. Owners/Admins invite by email (email-primary),
 * change roles (anti-escalation enforced server-side AND reflected here), and
 * offboard. The offboard confirm states the real, honest semantics (forward-only,
 * not a remote wipe). Read-only for Members/Partners/Guests.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Avatar, Btn, RoleGlyph, SurfBadge } from "@/components/primitives";
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

function InviteDialog({
  workspaceId,
  onClose,
  onDone,
}: {
  workspaceId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("Member");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [manualLink, setManualLink] = useState<string | null>(null);

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/invites`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ workspaceId, email: email.trim(), role }),
      });
      const data = (await r.json().catch(() => ({}))) as {
        emailSent?: boolean;
        suppressed?: boolean;
        link?: string;
        error?: string;
      };
      if (!r.ok) {
        setError(r.status === 429 ? "Too many invites — wait a moment." : "Couldn't send the invite.");
        return;
      }
      if (data.suppressed) {
        setError(
          `${email.trim()} previously unsubscribed from Citrate emails, so we didn't send one. Reach them another way, or they can ask larry@citrate.ai to resubscribe.`,
        );
        return;
      }
      if (data.emailSent) {
        onDone();
        onClose();
      } else {
        // SMTP not configured — show the one-time link to copy/share manually.
        setManualLink(data.link ?? null);
      }
    } catch {
      setError("Network error — please retry.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.scrim} onClick={onClose}>
      <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={styles.dialogHead}>Invite a teammate</div>
        {manualLink ? (
          <div className={styles.manual}>
            <p className={styles.manualNote}>
              Email isn&apos;t configured on this deployment. Share this one-time link with your teammate:
            </p>
            <SelectableText>{manualLink}</SelectableText>
            <div className={styles.dialogFoot}>
              <Btn variant="primary" onClick={onDone}>
                Done
              </Btn>
            </div>
          </div>
        ) : (
          <form onSubmit={invite} className={styles.form}>
            <label className={styles.field}>
              <span className={styles.fieldLabel}>Email</span>
              <input
                className={styles.input}
                type="email"
                placeholder="teammate@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                required
              />
            </label>
            <label className={styles.field}>
              <span className={styles.fieldLabel}>Role</span>
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
              <Btn variant="primary" type="submit" disabled={busy || !email.trim()}>
                {busy ? "Sending…" : "Send invite"}
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
