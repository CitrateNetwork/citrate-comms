"use client";

/**
 * MEN-2 — notification bell. Live over SSE (E-5 WP-2) with the original 20s poll
 * as the fallback transport: no EventSource support, or a dead stream, reverts to
 * polling. Duplicate suppression across the transport switch lives in NotifFeed.
 * Opens a dropdown of recent pings and marks them read on open. Each ping links
 * to the channel it came from (we store no message content — the recipient reads
 * it in context).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/primitives";
import { NotifFeed } from "@/lib/realtime/notif-feed";
import type { NotifyEvent } from "@/lib/realtime/notify-events";
import { groupNotifs, type NotifItem as Notif } from "@/lib/notif-group";
import styles from "./NotifBell.module.css";

const POLL_MS = 20000;

export function NotifBell({ workspaceId, workspaceSlug }: { workspaceId: string; workspaceSlug: string }) {
  const router = useRouter();
  const api = `/api/workspaces/${workspaceId}/notifications`;
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [items, setItems] = useState<Notif[]>([]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const ref = useRef<HTMLDivElement>(null);
  // One feed per mount: dedups notification ids across SSE ⇄ poll switches.
  const feedRef = useRef<NotifFeed | null>(null);
  feedRef.current ??= new NotifFeed();

  const poll = useCallback(async () => {
    try {
      const r = await fetch(`${api}?count=1`, { cache: "no-store" });
      if (r.ok) {
        const feed = feedRef.current!;
        feed.ingest({ type: "unread", unread: ((await r.json()) as { unread: number }).unread ?? 0 });
        setUnread(feed.unread);
      }
    } catch {
      /* transient */
    }
  }, [api]);

  // Transport: SSE when available, the legacy 20s poll otherwise (or on SSE death).
  useEffect(() => {
    const feed = feedRef.current!;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setInterval> | null = null;
    let disposed = false;

    const startPoll = () => {
      if (disposed || timer) return;
      void poll();
      timer = setInterval(() => void poll(), POLL_MS);
    };

    if (typeof EventSource === "undefined") {
      // Feature-detect: no SSE support → the original poll transport.
      startPoll();
    } else {
      es = new EventSource(`${api}/stream`);
      es.onmessage = (m) => {
        try {
          const event = JSON.parse(m.data as string) as NotifyEvent;
          feed.ingest(event); // dedups; unread events are absolute snapshots
          setUnread(feed.unread);
        } catch {
          /* malformed frame — ignore */
        }
      };
      es.onerror = () => {
        // CONNECTING = the browser is auto-reconnecting (e.g. the stream's normal
        // lifetime rollover) — leave it alone. CLOSED = fatal: revert to the poll.
        if (es && es.readyState === EventSource.CLOSED) {
          es.close();
          es = null;
          startPoll();
        }
      };
      // Prime the badge immediately; the stream's first event reconciles it.
      void poll();
    }

    return () => {
      disposed = true;
      es?.close();
      if (timer) clearInterval(timer);
    };
  }, [api, poll]);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (!next) return;
    try {
      const r = await fetch(api, { cache: "no-store" });
      if (r.ok) {
        const j = (await r.json()) as { items: Notif[] };
        setItems(j.items ?? []);
      }
      // Opening the tray clears the badge.
      await fetch(api, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ all: true }) });
      feedRef.current!.clear();
      setUnread(0);
    } catch {
      /* ignore */
    }
  }

  function go(n: Notif) {
    setOpen(false);
    if (n.kind === "task_assigned") {
      router.push(`/w/${workspaceSlug}/pm${n.taskId ? `?task=${n.taskId}` : ""}`);
    } else if (n.channelId) {
      router.push(`/w/${workspaceSlug}/comms/${n.channelId}`);
    }
  }

  const groups = groupNotifs(items);
  function toggleGroup(key: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div className={styles.wrap} ref={ref}>
      <button className={styles.bell} onClick={toggle} aria-label="Notifications" title="Notifications">
        <Icon name="bell" size={16} />
        {unread > 0 && <span className={styles.badge}>{unread > 9 ? "9+" : unread}</span>}
      </button>
      {open && (
        <div className={styles.tray}>
          <div className={styles.trayHead}>Notifications</div>
          {items.length === 0 ? (
            <div className={styles.empty}>No notifications yet.</div>
          ) : (
            <div className={styles.list}>
              {groups.map((g) => {
                const isCollapsed = collapsed.has(g.key);
                return (
                  <div key={g.key} className={styles.group}>
                    <button className={styles.groupHead} onClick={() => toggleGroup(g.key)} aria-expanded={!isCollapsed}>
                      <span className={styles.caret} aria-hidden="true">{isCollapsed ? "▸" : "▾"}</span>
                      <Icon name={g.icon} size={13} />
                      <span className={styles.groupName}>{g.name}</span>
                      {g.unread > 0 && <span className={styles.groupCount}>{g.unread}</span>}
                    </button>
                    {!isCollapsed &&
                      g.items.map((n) => (
                        <button key={n.id} className={`${styles.item} ${n.read ? "" : styles.unreadItem}`} onClick={() => go(n)}>
                          <Icon name={n.kind === "task_assigned" ? "projects" : "at"} size={13} />
                          <span className={styles.text}>
                            {n.kind === "task_assigned" ? (
                              <><strong>{n.actorName ?? "Someone"}</strong> assigned you a task</>
                            ) : (
                              <><strong>{n.actorName ?? "Someone"}</strong> mentioned you</>
                            )}
                          </span>
                          <span className={styles.when}>{new Date(n.createdAt).toLocaleDateString()}</span>
                        </button>
                      ))}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
