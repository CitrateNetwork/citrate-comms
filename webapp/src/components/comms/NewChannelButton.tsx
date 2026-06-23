"use client";

/**
 * "+ New channel / DM" — inline create flow in the rail. Pick a kind, then (for a DM,
 * required; for a channel/forum, optional) choose participants from a member + agent
 * picker with @-search. DMs are PRIVATE: only the people you seat here can see them
 * (the rail lists channels by membership; channel routes guard on channel membership).
 * The creator is always seated server-side.
 */
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Icon, SurfBadge } from "@/components/primitives";
import styles from "./NewChannelButton.module.css";

type Kind = "channel" | "forum" | "dm";

interface RosterEntry {
  sub: string;
  displayName: string;
  role: string;
  isAgent: boolean;
  status: string;
}

export function NewChannelButton({
  workspaceId,
  workspaceSlug,
  meSub,
  canCreateChannel = true,
  canCreateDm = true,
}: {
  workspaceId: string;
  workspaceSlug: string;
  meSub?: string;
  canCreateChannel?: boolean;
  canCreateDm?: boolean;
}) {
  const router = useRouter();
  // Which kinds this caller may create. Members/Partners get DM-only; Owner/Admin get all.
  const availableKinds: Kind[] = [
    ...(canCreateChannel ? (["channel", "forum"] as const) : []),
    ...(canCreateDm ? (["dm"] as const) : []),
  ];
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Kind>(availableKinds[0] ?? "dm");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Record<string, RosterEntry>>({});
  const [roster, setRoster] = useState<RosterEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load the roster (members + agents) once when the dialog opens.
  useEffect(() => {
    if (!open || roster.length > 0) return;
    let cancelled = false;
    fetch(`/api/workspaces/${workspaceId}/members`)
      .then((r) => (r.ok ? r.json() : { members: [] }))
      .then((j: { members?: RosterEntry[] }) => {
        if (!cancelled) setRoster(j.members ?? []);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [open, workspaceId, roster.length]);

  const selectedList = Object.values(selected);
  const isDm = kind === "dm";

  const candidates = useMemo(() => {
    const q = query.replace(/^@+/, "").trim().toLowerCase();
    return roster
      .filter((m) => m.status === "active")
      .filter((m) => m.sub !== meSub) // creator is auto-seated
      .filter((m) => !selected[m.sub])
      .filter((m) => (q ? m.displayName.toLowerCase().includes(q) : true))
      .slice(0, 8);
  }, [roster, query, selected, meSub]);

  function pick(m: RosterEntry) {
    setSelected((s) => ({ ...s, [m.sub]: m }));
    setQuery("");
  }
  function unpick(sub: string) {
    setSelected((s) => {
      const next = { ...s };
      delete next[sub];
      return next;
    });
  }

  function reset() {
    setOpen(false);
    setName("");
    setQuery("");
    setSelected({});
    setError(null);
    setKind(availableKinds[0] ?? "dm");
  }

  function derivedName(): string {
    if (!isDm) return name.trim();
    const names = selectedList.map((m) => m.displayName);
    const joined = names.join(", ");
    return (joined || "Direct message").slice(0, 60);
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (isDm && selectedList.length === 0) {
      setError("Pick at least one person or agent for the DM.");
      return;
    }
    if (!isDm && name.trim().length < 1) {
      setError("Give the channel a name.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/channels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId,
          kind,
          name: derivedName(),
          memberSubs: selectedList.map((m) => m.sub),
        }),
      });
      if (!r.ok) {
        setError(r.status === 403 ? "You don't have permission." : "Couldn't create it.");
        return;
      }
      const { channel } = (await r.json()) as { channel: { id: string } };
      reset();
      router.push(`/w/${workspaceSlug}/comms/${channel.id}`);
      router.refresh();
    } catch {
      setError("Network error — please retry.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button className={styles.add} aria-label="New channel or DM" onClick={() => setOpen(true)}>
        <Icon name="plus" size={14} />
      </button>
      {open && (
        <div className={styles.scrim} onClick={reset}>
          <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
            <div className={styles.title}>{isDm ? "New direct message" : "New channel"}</div>
            <form onSubmit={create} className={styles.form}>
              {availableKinds.length > 1 && (
                <div className={styles.kinds}>
                  {availableKinds.map((k) => (
                    <button
                      type="button"
                      key={k}
                      className={`${styles.kindBtn} ${kind === k ? styles.kindActive : ""}`}
                      onClick={() => {
                        setKind(k);
                        setError(null);
                      }}
                    >
                      {k === "dm" ? "DM" : k}
                    </button>
                  ))}
                </div>
              )}

              {!isDm && (
                <input
                  className={styles.input}
                  placeholder="e.g. deals"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoFocus
                  maxLength={60}
                />
              )}

              {/* Participant picker — required for DMs, optional for channels/forums. */}
              <div className={styles.picker}>
                <div className={styles.pickerLabel}>
                  {isDm ? "People & agents" : "Add people & agents (optional)"}
                  {isDm && <span className={styles.privacy}><Icon name="lock" size={11} /> private</span>}
                </div>

                {selectedList.length > 0 && (
                  <div className={styles.chips}>
                    {selectedList.map((m) => (
                      <span key={m.sub} className={styles.chip}>
                        {m.isAgent && <SurfBadge variant="agent">AGENT</SurfBadge>}
                        @{m.displayName}
                        <button type="button" className={styles.chipX} onClick={() => unpick(m.sub)} aria-label={`Remove ${m.displayName}`}>
                          <Icon name="x" size={11} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}

                <input
                  className={styles.input}
                  placeholder="@ search members & agents"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  autoFocus={isDm}
                />

                {query.trim() !== "" && (
                  <div className={styles.results}>
                    {candidates.length === 0 ? (
                      <div className={styles.noResults}>No matches</div>
                    ) : (
                      candidates.map((m) => (
                        <button type="button" key={m.sub} className={styles.resultRow} onClick={() => pick(m)}>
                          <Icon name={m.isAgent ? "agents" : "user"} size={14} />
                          <span className={styles.resultName}>{m.displayName}</span>
                          {m.isAgent ? (
                            <SurfBadge variant="agent">AGENT</SurfBadge>
                          ) : (
                            <span className={styles.resultRole}>{m.role}</span>
                          )}
                        </button>
                      ))
                    )}
                  </div>
                )}
              </div>

              {error && <div className={styles.error}>{error}</div>}
              <div className={styles.actions}>
                <button type="button" className="btn btn-quiet sm" onClick={reset}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary sm"
                  disabled={busy || (isDm ? selectedList.length === 0 : !name.trim())}
                >
                  {busy ? "Creating…" : isDm ? "Start DM" : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
