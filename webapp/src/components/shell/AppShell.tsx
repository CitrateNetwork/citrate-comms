"use client";

/**
 * Responsive app shell — titlebar + left rail + content. The native design is
 * fixed-px desktop; this version collapses the rail into a drawer below 880px
 * (the one deliberate change for the web surface). Carries the honest trust-boundary
 * marker in the titlebar ("Web · team-trusted"), distinct from the native server-blind
 * posture. Nav + spaces are real (empty until populated) — no mock data.
 */
import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon, SurfBadge, SevDot } from "@/components/primitives";
import type { IconName } from "@/components/primitives";
import { NewChannelButton } from "@/components/comms/NewChannelButton";
import { NotifBell } from "./NotifBell";
import { DragDropGuard } from "./DragDropGuard";
import styles from "./AppShell.module.css";

export interface SpaceLink {
  id: string;
  name: string;
  kind: "channel" | "forum" | "dm";
  unread?: number;
  hasAgent?: boolean;
}

export interface ShellProps {
  workspaceId: string;
  workspaceSlug: string;
  workspaceName: string;
  role: string;
  meSub?: string;
  canCreateChannel?: boolean;
  canCreateDm?: boolean;
  canApprove?: boolean;
  approvalsCount?: number;
  spaces?: SpaceLink[];
  children: React.ReactNode;
}

const NAV: { key: string; label: string; icon: IconName }[] = [
  { key: "crm", label: "CRM", icon: "crm" },
  { key: "pm", label: "Projects", icon: "projects" },
  { key: "agents", label: "Agents", icon: "agents" },
  { key: "approvals", label: "Approvals", icon: "bell" },
  { key: "members", label: "Members", icon: "user" },
  { key: "audit", label: "Audit", icon: "audit" },
  { key: "settings", label: "Settings", icon: "settings" },
];

export function AppShell({
  workspaceId,
  workspaceSlug,
  workspaceName,
  role,
  meSub,
  canCreateChannel = false,
  canCreateDm = false,
  canApprove = false,
  approvalsCount = 0,
  spaces = [],
  children,
}: ShellProps) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const pathname = usePathname() ?? "";
  const base = `/w/${workspaceSlug}`;
  const nav = NAV.filter((n) => n.key !== "approvals" || canApprove);
  const active = nav.find((n) => pathname.startsWith(`${base}/${n.key}`))?.key ?? "comms";

  return (
    <div className={styles.win}>
      <DragDropGuard />
      <header className={styles.titlebar}>
        <div className={styles.tbLeft}>
          <button className={styles.burger} aria-label="Menu" onClick={() => setDrawerOpen((v) => !v)}>
            <Icon name="dots" size={18} />
          </button>
          <Link href="/w" className={styles.brand}>
            ◐ <span className={styles.wsName}>{workspaceName}</span>
          </Link>
        </div>
        <div className={styles.tbRight}>
          <SurfBadge variant="outline">Web · team-trusted</SurfBadge>
          <span className={styles.conn}>
            <SevDot level="pass" /> Connected
          </span>
          <NotifBell workspaceId={workspaceId} workspaceSlug={workspaceSlug} />
          {/* Sign-out is a POST form, NOT a <Link> — a GET logout gets prefetched/
              preloaded by the router and browser, silently clearing the session. */}
          <form action="/auth/logout" method="post" className={styles.meForm}>
            <button type="submit" className={styles.me} title="Sign out" aria-label="Sign out">
              <Icon name="logout" size={16} />
            </button>
          </form>
        </div>
      </header>

      <div className={styles.body}>
        <nav className={`${styles.rail} ${drawerOpen ? styles.railOpen : ""}`}>
          <div className={styles.railSection}>
            <div className={styles.railHeadRow}>
              <span className={styles.railHead}>Spaces</span>
              {(canCreateChannel || canCreateDm) && (
                <NewChannelButton
                  workspaceId={workspaceId}
                  workspaceSlug={workspaceSlug}
                  meSub={meSub}
                  canCreateChannel={canCreateChannel}
                  canCreateDm={canCreateDm}
                />
              )}
            </div>
            {spaces.length === 0 && <div className={styles.railEmpty}>No channels yet</div>}
            {spaces.map((s) => (
              <Link
                key={s.id}
                href={`${base}/comms/${s.id}`}
                className={styles.railItem}
                onClick={() => setDrawerOpen(false)}
              >
                <Icon name={s.kind === "forum" ? "forum" : s.kind === "dm" ? "dm" : "hash"} size={15} />
                <span className={styles.railLabel}>{s.name}</span>
                {s.hasAgent && <SurfBadge variant="agent">AGENT</SurfBadge>}
                {s.unread ? <span className={styles.unread}>{s.unread}</span> : null}
              </Link>
            ))}
          </div>

          <div className={styles.railSection}>
            <div className={styles.railHead}>Workspace</div>
            {nav.map((n) => (
              <Link
                key={n.key}
                href={`${base}/${n.key}`}
                className={`${styles.railItem} ${active === n.key ? styles.railActive : ""}`}
                onClick={() => setDrawerOpen(false)}
              >
                <Icon name={n.icon} size={15} />
                <span className={styles.railLabel}>{n.label}</span>
                {n.key === "approvals" && approvalsCount > 0 ? <span className={styles.unread}>{approvalsCount}</span> : null}
              </Link>
            ))}
          </div>

          <div className={styles.railFoot}>
            <span className={styles.roleTag}>{role}</span>
          </div>
        </nav>

        {drawerOpen && <div className={styles.scrim} onClick={() => setDrawerOpen(false)} />}

        <main className={styles.content}>{children}</main>
      </div>
    </div>
  );
}
