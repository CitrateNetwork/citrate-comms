"use client";

/**
 * CH-1 — org-wide agent-conversation directory + read-only viewer. Owner/Admin see every
 * member's saved chats (and can filter by persona or member); members see only their own.
 * Opening a thread loads its transcript read-only (the admin read is itself audited server
 * side). Incognito chats are never persisted, so they never appear here.
 */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Avatar, Icon } from "@/components/primitives";
import { Markdown } from "./Markdown";
import s from "@/components/common/screen.module.css";
import styles from "./AgentHistoryScreen.module.css";

interface ThreadRow {
  id: string;
  title: string;
  personaId: string | null;
  personaName: string | null;
  invokedBySub: string;
  invokedByName: string | null;
  createdAt: string;
}
interface Msg {
  id: string;
  role: string;
  content: string;
}

export function AgentHistoryScreen({
  workspaceId,
  workspaceSlug,
  viewAll,
  threads: initial,
  personas,
  members,
}: {
  workspaceId: string;
  workspaceSlug: string;
  viewAll: boolean;
  threads: ThreadRow[];
  personas: { id: string; name: string }[];
  members: { sub: string; name: string }[];
}) {
  const [threads, setThreads] = useState<ThreadRow[]>(initial);
  const [personaId, setPersonaId] = useState("");
  const [memberSub, setMemberSub] = useState("");
  const [q, setQ] = useState("");
  const [loadingList, setLoadingList] = useState(false);

  const [active, setActive] = useState<ThreadRow | null>(null);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [loadingThread, setLoadingThread] = useState(false);

  const refetch = useCallback(async () => {
    setLoadingList(true);
    try {
      const params = new URLSearchParams();
      if (personaId) params.set("personaId", personaId);
      if (memberSub) params.set("memberSub", memberSub);
      const r = await fetch(`/api/workspaces/${workspaceId}/agents/history?${params.toString()}`);
      const j = (await r.json()) as { threads?: ThreadRow[] };
      setThreads(j.threads ?? []);
    } catch {
      /* ignore */
    } finally {
      setLoadingList(false);
    }
  }, [workspaceId, personaId, memberSub]);

  // Refetch when the server-side filters change (skip the very first render — SSR seeded it).
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    if (!mounted) {
      setMounted(true);
      return;
    }
    void refetch();
  }, [personaId, memberSub, mounted, refetch]);

  async function open(t: ThreadRow) {
    setActive(t);
    setLoadingThread(true);
    setMessages([]);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/agents/threads/${t.id}/messages`);
      if (!r.ok) {
        setMessages([{ id: "err", role: "system", content: "_Couldn't load this conversation._" }]);
        return;
      }
      const j = (await r.json()) as { messages?: Msg[] };
      setMessages((j.messages ?? []).filter((m) => m.role === "user" || m.role === "assistant"));
    } catch {
      setMessages([{ id: "err", role: "system", content: "_Couldn't load this conversation._" }]);
    } finally {
      setLoadingThread(false);
    }
  }

  const ql = q.trim().toLowerCase();
  const shown = ql
    ? threads.filter(
        (t) =>
          t.title.toLowerCase().includes(ql) ||
          (t.personaName ?? "").toLowerCase().includes(ql) ||
          (t.invokedByName ?? "").toLowerCase().includes(ql),
      )
    : threads;

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <div className={s.eyebrow}>
            <Link href={`/w/${workspaceSlug}/agents`} className={styles.back}>
              Agents
            </Link>{" "}
            / Conversation history
          </div>
          <h1 className={s.title}>Conversation history</h1>
        </div>
      </header>

      <div className={styles.note}>
        {viewAll
          ? "You can see every member's saved agent conversations. Opening one is recorded in the audit log. Incognito chats are never saved and don't appear here."
          : "Your saved agent conversations. Incognito chats are never saved and don't appear here."}
      </div>

      <div className={styles.filters}>
        <input className={styles.search} placeholder="Search title, agent, or member…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className={styles.select} value={personaId} onChange={(e) => setPersonaId(e.target.value)} aria-label="Filter by agent">
          <option value="">All agents</option>
          {personas.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        {viewAll && members.length > 0 && (
          <select className={styles.select} value={memberSub} onChange={(e) => setMemberSub(e.target.value)} aria-label="Filter by member">
            <option value="">All members</option>
            {members.map((m) => (
              <option key={m.sub} value={m.sub}>
                {m.name}
              </option>
            ))}
          </select>
        )}
      </div>

      <div className={styles.split}>
        <div className={styles.list}>
          {loadingList ? (
            <div className={styles.empty}>Loading…</div>
          ) : shown.length === 0 ? (
            <div className={styles.empty}>No conversations match.</div>
          ) : (
            shown.map((t) => (
              <button
                key={t.id}
                className={`${styles.item} ${active?.id === t.id ? styles.itemActive : ""}`}
                onClick={() => open(t)}
              >
                <div className={styles.itemTitle}>{t.title}</div>
                <div className={styles.itemMeta}>
                  <span className={styles.persona}>{t.personaName ?? "agent"}</span>
                  {viewAll && <span className={styles.dot}>·</span>}
                  {viewAll && <span>{t.invokedByName ?? "member"}</span>}
                  <span className={styles.dot}>·</span>
                  <span>{new Date(t.createdAt).toLocaleString()}</span>
                </div>
              </button>
            ))
          )}
        </div>

        <div className={styles.viewer}>
          {!active ? (
            <div className={styles.viewerEmpty}>
              <Icon name="audit" size={20} />
              <p>Select a conversation to read it.</p>
            </div>
          ) : (
            <>
              <div className={styles.viewerHead}>
                <div className={styles.viewerTitle}>{active.title}</div>
                <div className={styles.viewerSub}>
                  {active.personaName ?? "agent"}
                  {viewAll ? ` · ${active.invokedByName ?? "member"}` : ""} · read-only
                </div>
              </div>
              <div className={styles.transcript}>
                {loadingThread ? (
                  <div className={styles.empty}>Loading…</div>
                ) : messages.length === 0 ? (
                  <div className={styles.empty}>No messages.</div>
                ) : (
                  messages.map((m) => (
                    <div key={m.id} className={`${styles.msg} ${m.role === "user" ? styles.user : styles.assistant}`}>
                      <div className={styles.msgWho}>
                        {m.role === "assistant" ? (
                          <Avatar name={active.personaName ?? "Agent"} size="sm" isAgent />
                        ) : (
                          <Avatar name={active.invokedByName ?? "Member"} size="sm" />
                        )}
                      </div>
                      <div className={styles.bubble}>
                        <Markdown>{m.content}</Markdown>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
