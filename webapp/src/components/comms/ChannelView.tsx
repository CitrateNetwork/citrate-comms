"use client";

/**
 * The core comms screen — message stream + composer + the witness Ledger panel.
 * Trusted-tier: messages are fetched as plaintext from the BFF (the server can read
 * them; that's the honest web posture). Live updates use incremental polling behind
 * a single hook so the transport can later swap to SSE without touching this view.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Avatar, Btn, IconBtn, RoleGlyph, SurfBadge, Icon } from "@/components/primitives";
import type { Role } from "@/lib/rbac/matrix";
import styles from "./ChannelView.module.css";

export interface UiMessage {
  id: string;
  authorSub: string;
  fromAgent: boolean;
  body: string;
  seq: number;
  onBehalfOf: string | null;
  createdAt: string;
}

export interface UiLedgerEntry {
  id: string;
  kind: "decision" | "commitment" | "resolved";
  text: string;
  bySub: string;
  status: "open" | "done";
  createdAt: string;
}

export interface DirEntry {
  displayName: string;
  role: Role;
  isAgent: boolean;
}

export interface ChannelViewProps {
  channelId: string;
  channelName: string;
  topic: string | null;
  mySub: string;
  canPost: boolean;
  initialMessages: UiMessage[];
  initialLedger: UiLedgerEntry[];
  directory: Record<string, DirEntry>;
}

const POLL_MS = 3000;

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function ChannelView(props: ChannelViewProps) {
  const [messages, setMessages] = useState<UiMessage[]>(props.initialMessages);
  const [ledger, setLedger] = useState<UiLedgerEntry[]>(props.initialLedger);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [witnessFor, setWitnessFor] = useState<UiMessage | null>(null);
  const streamRef = useRef<HTMLDivElement>(null);
  const lastSeq = useRef<number>(props.initialMessages.at(-1)?.seq ?? 0);

  const nameOf = useCallback(
    (sub: string) => props.directory[sub]?.displayName ?? sub.slice(0, 8),
    [props.directory],
  );

  const scrollToEnd = useCallback(() => {
    requestAnimationFrame(() => {
      if (streamRef.current) streamRef.current.scrollTop = streamRef.current.scrollHeight;
    });
  }, []);

  useEffect(scrollToEnd, [scrollToEnd]);

  // Live poll for new messages after the last seq we hold.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await fetch(`/api/channels/${props.channelId}/messages?after=${lastSeq.current}`, {
          cache: "no-store",
        });
        if (!alive || !r.ok) return;
        const { messages: fresh } = (await r.json()) as { messages: UiMessage[] };
        if (fresh.length) {
          lastSeq.current = fresh.at(-1)!.seq;
          setMessages((prev) => dedupe([...prev, ...fresh]));
          scrollToEnd();
        }
      } catch {
        /* transient — next tick retries */
      }
    };
    const h = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(h);
    };
  }, [props.channelId, scrollToEnd]);

  async function send() {
    const body = draft.trim();
    if (!body || sending) return;
    setSending(true);
    setDraft("");
    try {
      const r = await fetch(`/api/channels/${props.channelId}/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, clientMsgId: crypto.randomUUID() }),
      });
      if (r.ok) {
        const { message } = (await r.json()) as { message: UiMessage };
        lastSeq.current = Math.max(lastSeq.current, message.seq);
        setMessages((prev) => dedupe([...prev, message]));
        scrollToEnd();
      } else {
        setDraft(body); // restore on failure
      }
    } catch {
      setDraft(body);
    } finally {
      setSending(false);
    }
  }

  async function submitWitness(kind: UiLedgerEntry["kind"], text: string) {
    if (!witnessFor) return;
    const src = witnessFor;
    setWitnessFor(null);
    try {
      const r = await fetch(`/api/channels/${props.channelId}/ledger`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sourceMessageId: src.id, kind, text }),
      });
      if (r.ok) {
        const { entry } = (await r.json()) as { entry: UiLedgerEntry };
        setLedger((prev) => [entry, ...prev]);
      }
    } catch {
      /* ignore — user can retry */
    }
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.main}>
        <header className={styles.head}>
          <div>
            <div className={styles.chanName}>
              <Icon name="hash" size={16} /> {props.channelName}
            </div>
            {props.topic && <div className={styles.topic}>{props.topic}</div>}
          </div>
          <SurfBadge variant="e2e">Encrypted</SurfBadge>
        </header>

        <div className={styles.stream} ref={streamRef}>
          {messages.length === 0 && (
            <div className={styles.empty}>
              This is the beginning of <strong>#{props.channelName}</strong>. Say hello.
            </div>
          )}
          {messages.map((m, i) => {
            const grouped = i > 0 && messages[i - 1]!.authorSub === m.authorSub && !m.onBehalfOf;
            const dir = props.directory[m.authorSub];
            const author = m.onBehalfOf ? `${nameOf(m.onBehalfOf)} (via Web Gateway)` : nameOf(m.authorSub);
            return (
              <div key={m.id} className={`${styles.msg} ${grouped ? styles.grouped : ""} ${m.fromAgent ? styles.agent : ""}`}>
                <div className={styles.gutter}>
                  {!grouped && <Avatar name={author} size="sm" isAgent={m.fromAgent} />}
                </div>
                <div className={styles.msgBody}>
                  {!grouped && (
                    <div className={styles.msgHead}>
                      <span className={styles.author}>{author}</span>
                      {dir && <RoleGlyph role={dir.role} />}
                      {m.fromAgent && <SurfBadge variant="agent">AGENT</SurfBadge>}
                      <span className={styles.ts}>{fmtTime(m.createdAt)}</span>
                    </div>
                  )}
                  <div className={styles.text}>{m.body}</div>
                </div>
                {props.canPost && (
                  <button className={styles.witnessBtn} title="Witness this" onClick={() => setWitnessFor(m)}>
                    <Icon name="check" size={14} />
                  </button>
                )}
              </div>
            );
          })}
        </div>

        {props.canPost ? (
          <div className={styles.composer}>
            <textarea
              className={styles.input}
              placeholder={`Message #${props.channelName}`}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                  e.preventDefault();
                  send();
                }
              }}
              rows={1}
            />
            <div className={styles.composerBar}>
              <SurfBadge variant="e2e">Encrypted</SurfBadge>
              <Btn variant="primary" size="sm" icon="send" onClick={send} disabled={sending || !draft.trim()}>
                Send
              </Btn>
            </div>
          </div>
        ) : (
          <div className={styles.readonly}>You have read-only access to this channel.</div>
        )}
      </div>

      <aside className={styles.ledger}>
        <div className={styles.ledgerHead}>Ledger</div>
        {ledger.length === 0 && (
          <div className={styles.ledgerEmpty}>
            Witnessed decisions and commitments appear here — a permanent, hashed record.
          </div>
        )}
        {ledger.map((e) => (
          <div key={e.id} className={`${styles.ledgerEntry} ${styles[`lk_${e.kind}`] ?? ""}`}>
            <div className={styles.ledgerKind}>{e.kind}</div>
            <div className={styles.ledgerText}>{e.text}</div>
            <div className={styles.ledgerMeta}>
              {nameOf(e.bySub)} · {fmtTime(e.createdAt)}
              {e.status === "done" && <span className={styles.done}> · done</span>}
            </div>
          </div>
        ))}
      </aside>

      {witnessFor && <WitnessDialog message={witnessFor} onCancel={() => setWitnessFor(null)} onSubmit={submitWitness} />}
    </div>
  );
}

function dedupe(list: UiMessage[]): UiMessage[] {
  const seen = new Set<string>();
  const out: UiMessage[] = [];
  for (const m of list) {
    if (seen.has(m.id)) continue;
    seen.add(m.id);
    out.push(m);
  }
  return out.sort((a, b) => a.seq - b.seq);
}

function WitnessDialog({
  message,
  onCancel,
  onSubmit,
}: {
  message: UiMessage;
  onCancel: () => void;
  onSubmit: (kind: UiLedgerEntry["kind"], text: string) => void;
}) {
  const [kind, setKind] = useState<UiLedgerEntry["kind"]>("decision");
  const [text, setText] = useState(message.body);
  return (
    <div className={styles.scrim} onClick={onCancel}>
      <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={styles.dialogHead}>
          Witness this <IconBtn name="x" onClick={onCancel} />
        </div>
        <div className={styles.kinds}>
          {(["decision", "commitment", "resolved"] as const).map((k) => (
            <button key={k} className={`${styles.kindBtn} ${kind === k ? styles.kindActive : ""}`} onClick={() => setKind(k)}>
              {k}
            </button>
          ))}
        </div>
        <textarea className={styles.dialogInput} value={text} onChange={(e) => setText(e.target.value)} rows={3} />
        <div className={styles.dialogFoot}>
          <Btn variant="quiet" onClick={onCancel}>
            Cancel
          </Btn>
          <Btn variant="primary" onClick={() => text.trim() && onSubmit(kind, text.trim())}>
            Record to ledger
          </Btn>
        </div>
      </div>
    </div>
  );
}
