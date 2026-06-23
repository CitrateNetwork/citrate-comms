"use client";

/**
 * Settings — the admin control surface. Sub-nav panes: Identity, Notifications,
 * Automation, Connection, Appearance. Workspace-level config (notifications,
 * automation, appearance defaults) is editable by the Owner (ManageWorkspace);
 * display name is editable by everyone (own profile). Appearance applies live via
 * the document data-* attributes the design system reads.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Btn, SurfBadge, SevDot } from "@/components/primitives";
import { SelectableText } from "@/components/primitives/SelectableText";
import type { WorkspaceSettings } from "@/lib/domain/settings";
import s from "@/components/common/screen.module.css";
import styles from "./SettingsScreen.module.css";

type Pane = "identity" | "notifications" | "automation" | "connection" | "appearance";

export interface Identity {
  displayName: string;
  walletAddress: string | null;
  email: string | null;
  role: string;
  kycStatus: string | null;
}
export interface ChannelOpt {
  id: string;
  name: string;
}

const PANES: { key: Pane; label: string }[] = [
  { key: "identity", label: "Identity" },
  { key: "notifications", label: "Notifications" },
  { key: "automation", label: "Automation" },
  { key: "connection", label: "Connection" },
  { key: "appearance", label: "Appearance" },
];

export function SettingsScreen({
  workspaceId,
  workspaceSlug,
  canManage,
  identity,
  settings,
  channels,
}: {
  workspaceId: string;
  workspaceSlug: string;
  canManage: boolean;
  identity: Identity;
  settings: WorkspaceSettings;
  channels: ChannelOpt[];
}) {
  const [pane, setPane] = useState<Pane>("identity");

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <div className={s.eyebrow}>Workspace</div>
          <h1 className={s.title}>Settings</h1>
        </div>
      </header>

      <div className={styles.layout}>
        <nav className={styles.subnav}>
          {PANES.map((p) => (
            <button key={p.key} className={`${styles.subnavItem} ${pane === p.key ? styles.subnavActive : ""}`} onClick={() => setPane(p.key)}>
              {p.label}
            </button>
          ))}
          <Link href={`/w/${workspaceSlug}/members`} className={styles.subnavItem}>
            Members & roles →
          </Link>
        </nav>

        <div className={styles.pane}>
          {pane === "identity" && <IdentityPane workspaceId={workspaceId} identity={identity} />}
          {pane === "notifications" && <NotificationsPane workspaceId={workspaceId} canManage={canManage} channels={channels} settings={settings} />}
          {pane === "automation" && <AutomationPane workspaceId={workspaceId} canManage={canManage} settings={settings} />}
          {pane === "connection" && <ConnectionPane />}
          {pane === "appearance" && <AppearancePane workspaceId={workspaceId} canManage={canManage} settings={settings} />}
        </div>
      </div>
    </div>
  );
}

function IdentityPane({ workspaceId, identity }: { workspaceId: string; identity: Identity }) {
  const router = useRouter();
  const [name, setName] = useState(identity.displayName);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  async function save() {
    setBusy(true);
    setSaved(false);
    const r = await fetch(`/api/workspaces/${workspaceId}/profile`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName: name.trim() }),
    });
    setBusy(false);
    if (r.ok) {
      setSaved(true);
      router.refresh();
    }
  }
  return (
    <div className={styles.section}>
      <h2 className={styles.h2}>Identity</h2>
      <label className={s.field}>
        <span className={s.fieldLabel}>Display name</span>
        <div className={styles.inline}>
          <input className={s.input} value={name} onChange={(e) => setName(e.target.value)} maxLength={60} />
          <Btn variant="primary" size="sm" onClick={save} disabled={busy || !name.trim() || name === identity.displayName}>
            {busy ? "Saving…" : saved ? "Saved" : "Save"}
          </Btn>
        </div>
      </label>
      <Row label="Wallet">{identity.walletAddress ? <SelectableText>{identity.walletAddress}</SelectableText> : <span className={styles.dim}>not linked</span>}</Row>
      <Row label="Email">{identity.email ?? <span className={styles.dim}>none</span>}</Row>
      <Row label="Role">{identity.role}</Row>
      <Row label="KYC">{identity.kycStatus ?? "none"}</Row>
    </div>
  );
}

function NotificationsPane({
  workspaceId,
  canManage,
  channels,
  settings,
}: {
  workspaceId: string;
  canManage: boolean;
  channels: ChannelOpt[];
  settings: WorkspaceSettings;
}) {
  const [prefs, setPrefs] = useState<Record<string, "all" | "mentions" | "mute">>(settings.notifications ?? {});
  async function set(channelId: string, level: "all" | "mentions" | "mute") {
    const next = { ...prefs, [channelId]: level };
    setPrefs(next);
    await fetch(`/api/workspaces/${workspaceId}/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ notifications: { [channelId]: level } }),
    });
  }
  return (
    <div className={styles.section}>
      <h2 className={styles.h2}>Notifications</h2>
      {!canManage && <p className={styles.dim}>Workspace notification defaults are set by the owner.</p>}
      {channels.length === 0 && <p className={styles.dim}>No channels yet.</p>}
      {channels.map((c) => (
        <Row key={c.id} label={`#${c.name}`}>
          <div className={styles.segmented}>
            {(["all", "mentions", "mute"] as const).map((lvl) => (
              <button
                key={lvl}
                disabled={!canManage}
                className={`${styles.segBtn} ${(prefs[c.id] ?? "all") === lvl ? styles.segActive : ""}`}
                onClick={() => set(c.id, lvl)}
              >
                {lvl}
              </button>
            ))}
          </div>
        </Row>
      ))}
    </div>
  );
}

function AutomationPane({ workspaceId, canManage, settings }: { workspaceId: string; canManage: boolean; settings: WorkspaceSettings }) {
  const [autoWitness, setAutoWitness] = useState(settings.automation?.autoWitness ?? false);
  async function toggle() {
    const next = !autoWitness;
    setAutoWitness(next);
    await fetch(`/api/workspaces/${workspaceId}/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ automation: { autoWitness: next } }),
    });
  }
  return (
    <div className={styles.section}>
      <h2 className={styles.h2}>Automation</h2>
      <div className={styles.toggleRow}>
        <div>
          <div className={styles.toggleLabel}>Agent auto-witness</div>
          <div className={styles.dim}>When on, agents may propose ledger entries (decisions/commitments) for review.</div>
        </div>
        <button
          className={`${styles.switch} ${autoWitness ? styles.switchOn : ""}`}
          disabled={!canManage}
          onClick={toggle}
          aria-pressed={autoWitness}
        >
          <span className={styles.knob} />
        </button>
      </div>
    </div>
  );
}

function ConnectionPane() {
  return (
    <div className={styles.section}>
      <h2 className={styles.h2}>Connection</h2>
      <div className={styles.trustCard}>
        <div className={styles.trustRow}>
          <SurfBadge variant="outline">Web</SurfBadge>
          <div>
            <strong>Team-trusted.</strong> This web tier stores messages and records encrypted at rest, and can
            read content to deliver it across your team&apos;s devices.
          </div>
        </div>
        <div className={styles.trustRow}>
          <SurfBadge variant="e2e">Native</SurfBadge>
          <div>
            <strong>Server-blind.</strong> The native app&apos;s relay routes ciphertext only — it can never read
            your messages. Both are end-to-end inside your team.
          </div>
        </div>
        <div className={styles.trustRow}>
          <SevDot level="idle" />
          <div>
            <strong>Sync gateway:</strong> not configured. When the workspace gateway is connected, web and native
            members share one workspace (a visible, audited gateway member).
          </div>
        </div>
      </div>
    </div>
  );
}

function AppearancePane({ workspaceId, canManage, settings }: { workspaceId: string; canManage: boolean; settings: WorkspaceSettings }) {
  const [density, setDensity] = useState(settings.appearance?.density ?? "cinematic");
  const [reducedMotion, setReducedMotion] = useState(settings.appearance?.reducedMotion ?? false);

  function apply(next: { density?: "cinematic" | "compact"; reducedMotion?: boolean }) {
    const root = document.documentElement;
    if (next.density) root.dataset.density = next.density;
    if (next.reducedMotion !== undefined) root.dataset.reducedMotion = String(next.reducedMotion);
  }
  async function persist(patch: { density?: "cinematic" | "compact"; reducedMotion?: boolean }) {
    if (!canManage) return;
    await fetch(`/api/workspaces/${workspaceId}/settings`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ appearance: patch }),
    });
  }
  return (
    <div className={styles.section}>
      <h2 className={styles.h2}>Appearance</h2>
      <Row label="Density">
        <div className={styles.segmented}>
          {(["cinematic", "compact"] as const).map((d) => (
            <button
              key={d}
              className={`${styles.segBtn} ${density === d ? styles.segActive : ""}`}
              onClick={() => {
                setDensity(d);
                apply({ density: d });
                persist({ density: d });
              }}
            >
              {d}
            </button>
          ))}
        </div>
      </Row>
      <Row label="Reduced motion">
        <button
          className={`${styles.switch} ${reducedMotion ? styles.switchOn : ""}`}
          onClick={() => {
            const next = !reducedMotion;
            setReducedMotion(next);
            apply({ reducedMotion: next });
            persist({ reducedMotion: next });
          }}
          aria-pressed={reducedMotion}
        >
          <span className={styles.knob} />
        </button>
      </Row>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className={styles.row}>
      <span className={styles.rowLabel}>{label}</span>
      <span className={styles.rowVal}>{children}</span>
    </div>
  );
}
