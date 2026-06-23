"use client";

/**
 * Agents directory — agents-as-members. Admins add an agent (creates a real Agent
 * member), pause/resume it, and seat it into channels (where it shows the AGENT
 * marker). Autonomous responses run via the comms-web-gateway / agent bridge
 * (Track C) — surfaced honestly here, not faked.
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Avatar, Btn, SurfBadge, SevDot } from "@/components/primitives";
import s from "@/components/common/screen.module.css";
import styles from "./AgentsScreen.module.css";

export interface UiAgent {
  id: string;
  memberSub: string;
  name: string;
  purpose: string | null;
  status: string;
  enabled: boolean;
  sponsorName: string | null;
}
export interface UiChannelOpt {
  id: string;
  name: string;
}
export interface UiPersona {
  id: string;
  name: string;
  key: string;
  baseTemplate: string;
  toolCount: number;
}

const PERSONA_BLURB: Record<string, string> = {
  "executive-assistant": "Keeps deals, tasks & commitments moving",
  "marketing-growth-engineer": "Researches markets & grows the pipeline",
  "data-scientist-notetaker": "Takes notes & runs analyses with provenance",
};

export function AgentsScreen({
  workspaceId,
  workspaceSlug,
  canManage,
  agents,
  channels,
  personas = [],
}: {
  workspaceId: string;
  workspaceSlug: string;
  canManage: boolean;
  agents: UiAgent[];
  channels: UiChannelOpt[];
  personas?: UiPersona[];
}) {
  const router = useRouter();
  const [adding, setAdding] = useState(false);

  async function toggle(agentId: string, enabled: boolean) {
    await fetch(`/api/workspaces/${workspaceId}/agents`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId, enabled }),
    });
    router.refresh();
  }

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <div className={s.eyebrow}>Workspace</div>
          <h1 className={s.title}>Agents</h1>
        </div>
        {canManage && (
          <Btn variant="primary" icon="plus" onClick={() => setAdding(true)}>
            Add agent
          </Btn>
        )}
      </header>

      <div className={styles.note}>
        Agents join as cryptographic <strong>members</strong>, not server-side bots — visible in rosters with an
        AGENT marker and recorded in the audit log. Every tool call an agent makes is audited; writes are
        approval-gated.
      </div>

      {personas.length > 0 && (
        <section className={styles.personas}>
          <div className={styles.personasHead}>Talk to a persona</div>
          <div className={styles.grid}>
            {personas.map((p) => (
              <Link key={p.id} href={`/w/${workspaceSlug}/agents/${p.id}`} className={styles.personaCard}>
                <div className={styles.cardHead}>
                  <Avatar name={p.name} size="md" isAgent />
                  <div>
                    <div className={styles.name}>{p.name}</div>
                    <div className={styles.statusRow}>{PERSONA_BLURB[p.baseTemplate] ?? `${p.toolCount} tools`}</div>
                  </div>
                </div>
                <div className={styles.chatCta}>
                  Chat <SurfBadge variant="agent">AGENT</SurfBadge>
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}

      {agents.length === 0 ? (
        <div className={s.empty}>No agents yet. {canManage ? "Add one to get started." : "An admin can add agents."}</div>
      ) : (
        <div className={styles.grid}>
          {agents.map((a) => (
            <div key={a.id} className={styles.card}>
              <div className={styles.cardHead}>
                <Avatar name={a.name} size="lg" isAgent />
                <div>
                  <div className={styles.name}>
                    {a.name} <SurfBadge variant="agent">AGENT</SurfBadge>
                  </div>
                  <div className={styles.statusRow}>
                    <SevDot level={a.enabled ? "pass" : "idle"} /> {a.status}
                  </div>
                </div>
              </div>
              {a.purpose && <p className={styles.purpose}>{a.purpose}</p>}
              {a.sponsorName && <div className={styles.sponsor}>Sponsored by {a.sponsorName}</div>}

              {canManage && (
                <div className={styles.actions}>
                  <AddToChannel agentSub={a.memberSub} channels={channels} onDone={() => router.refresh()} />
                  <Btn variant={a.enabled ? "ghost" : "primary"} size="sm" onClick={() => toggle(a.id, !a.enabled)}>
                    {a.enabled ? "Pause" : "Resume"}
                  </Btn>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {adding && <AddAgentDialog workspaceId={workspaceId} onClose={() => setAdding(false)} onDone={() => router.refresh()} />}
    </div>
  );
}

function AddToChannel({
  agentSub,
  channels,
  onDone,
}: {
  agentSub: string;
  channels: UiChannelOpt[];
  onDone: () => void;
}) {
  const [channelId, setChannelId] = useState(channels[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  if (channels.length === 0) return <span className={styles.noChan}>No channels yet</span>;
  async function add() {
    if (!channelId || busy) return;
    setBusy(true);
    const r = await fetch(`/api/channels/${channelId}/members`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sub: agentSub }),
    });
    setBusy(false);
    if (r.ok) onDone();
  }
  return (
    <div className={styles.addToChan}>
      <select className={styles.chanSelect} value={channelId} onChange={(e) => setChannelId(e.target.value)}>
        {channels.map((c) => (
          <option key={c.id} value={c.id}>
            #{c.name}
          </option>
        ))}
      </select>
      <Btn variant="ghost" size="sm" onClick={add} disabled={busy}>
        Add
      </Btn>
    </div>
  );
}

function AddAgentDialog({ workspaceId, onClose, onDone }: { workspaceId: string; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [busy, setBusy] = useState(false);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    const r = await fetch(`/api/workspaces/${workspaceId}/agents`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: name.trim(), purpose: purpose.trim() || undefined }),
    });
    setBusy(false);
    if (r.ok) {
      onDone();
      onClose();
    }
  }
  return (
    <div className={s.scrim} onClick={onClose}>
      <div className={s.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={s.dialogHead}>Add an agent</div>
        <form className={s.form} onSubmit={create}>
          <label className={s.field}>
            <span className={s.fieldLabel}>Name</span>
            <input className={s.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="@crm-agent" autoFocus />
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Purpose (optional)</span>
            <input className={s.input} value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="Summarizes deal threads" />
          </label>
          <div className={s.dialogFoot}>
            <Btn variant="quiet" type="button" onClick={onClose}>
              Cancel
            </Btn>
            <Btn variant="primary" type="submit" disabled={busy || !name.trim()}>
              Add agent
            </Btn>
          </div>
        </form>
      </div>
    </div>
  );
}
