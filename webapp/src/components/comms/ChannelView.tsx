"use client";

/**
 * The core comms screen — message stream + composer + the witness Ledger panel.
 * Trusted-tier: messages are fetched as plaintext from the BFF (the server can read
 * them; that's the honest web posture). Live updates use incremental polling behind
 * a single hook so the transport can later swap to SSE without touching this view.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Avatar, Btn, IconBtn, RoleGlyph, SurfBadge, Icon } from "@/components/primitives";
import { ComposerAttach } from "@/components/attachments/ComposerAttach";
import { Attachment } from "@/components/attachments/Attachment";
import type { UploadedDoc } from "@/components/attachments/uploadAttachment";
import type { Role } from "@/lib/rbac/matrix";
import { type Mentionable, filterMentionables, parseMentions, toHandle } from "@/lib/mentions";
import styles from "./ChannelView.module.css";

export interface UiAttachment {
  id: string;
  name: string;
  mime: string | null;
  url: string;
}

export interface UiMessage {
  id: string;
  authorSub: string;
  fromAgent: boolean;
  body: string;
  seq: number;
  onBehalfOf: string | null;
  attachments?: UiAttachment[];
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
  workspaceId: string;
  channelId: string;
  channelName: string;
  topic: string | null;
  mySub: string;
  canPost: boolean;
  initialMessages: UiMessage[];
  initialLedger: UiLedgerEntry[];
  directory: Record<string, DirEntry>;
  mentionables?: Mentionable[];
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
  const [pending, setPending] = useState<UploadedDoc[]>([]);
  const [sending, setSending] = useState(false);
  const [witnessFor, setWitnessFor] = useState<UiMessage | null>(null);
  const streamRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const lastSeq = useRef<number>(props.initialMessages.at(-1)?.seq ?? 0);

  // MEN-0/MEN-1: @-mention autocomplete + agents currently composing a channel reply.
  const mentionables = props.mentionables ?? [];
  const [mq, setMq] = useState<string | null>(null); // active @-query (null = closed)
  const [mIdx, setMIdx] = useState(0);
  const [thinkingAgents, setThinkingAgents] = useState<string[]>([]); // agent names mid-reply
  const suggestions = mq !== null ? filterMentionables(mentionables, mq) : [];

  /** Read the @-token immediately before the caret (if any) and open/close the popover. */
  function syncMention(value: string, caret: number) {
    const upto = value.slice(0, caret);
    const m = /(^|[^a-zA-Z0-9_])@([a-z0-9._-]*)$/i.exec(upto);
    if (m) {
      setMq(m[2]!.toLowerCase());
      setMIdx(0);
    } else {
      setMq(null);
    }
  }

  function applyMention(pick: Mentionable) {
    const el = inputRef.current;
    const caret = el ? el.selectionStart : draft.length;
    const before = draft.slice(0, caret).replace(/@([a-z0-9._-]*)$/i, `@${toHandle(pick.name)} `);
    const next = before + draft.slice(caret);
    setDraft(next);
    setMq(null);
    requestAnimationFrame(() => {
      if (el) {
        el.focus();
        el.selectionStart = el.selectionEnd = before.length;
      }
    });
  }

  /** After a human posts, call any @-mentioned agents into the channel (MEN-1). */
  async function pingMentionedAgents(body: string) {
    const { agents } = parseMentions(body, mentionables);
    if (agents.length === 0) return;
    setThinkingAgents((prev) => [...new Set([...prev, ...agents.map((a) => a.name)])]);
    await Promise.all(
      agents.map(async (a) => {
        try {
          const r = await fetch(`/api/channels/${props.channelId}/agent-reply`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ agentSub: a.sub }),
          });
          if (r.ok) {
            // The agent's message is fetched by the poll; nudge it immediately.
            const fresh = await fetch(`/api/channels/${props.channelId}/messages?after=${lastSeq.current}`, { cache: "no-store" });
            if (fresh.ok) {
              const { messages: rows } = (await fresh.json()) as { messages: UiMessage[] };
              if (rows.length) {
                lastSeq.current = rows.at(-1)!.seq;
                setMessages((prev) => dedupe([...prev, ...rows]));
                scrollToEnd();
              }
            }
          }
        } catch {
          /* poll will still pick up the reply if it lands late */
        } finally {
          setThinkingAgents((prev) => prev.filter((n) => n !== a.name));
        }
      }),
    );
  }

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
    if ((!body && pending.length === 0) || sending) return;
    setSending(true);
    setDraft("");
    const atts = pending;
    setPending([]);
    try {
      const r = await fetch(`/api/channels/${props.channelId}/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, clientMsgId: crypto.randomUUID(), attachmentIds: atts.map((a) => a.id) }),
      });
      if (r.ok) {
        const { message } = (await r.json()) as { message: UiMessage };
        lastSeq.current = Math.max(lastSeq.current, message.seq);
        setMessages((prev) => dedupe([...prev, message]));
        scrollToEnd();
        void pingMentionedAgents(body); // MEN-1: fire-and-forget; replies stream in via poll
      } else {
        setDraft(body); // restore on failure
        setPending(atts);
      }
    } catch {
      setDraft(body);
      setPending(atts);
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
                  {m.body && <div className={styles.text}>{m.body}</div>}
                  {m.attachments && m.attachments.length > 0 && (
                    <div className={styles.attachments}>
                      {m.attachments.map((a) => (
                        <Attachment
                          key={a.id}
                          compact
                          item={{ id: a.id, name: a.name, mime: a.mime, url: a.url, downloadUrl: `/api/workspaces/${props.workspaceId}/documents/${a.id}/download` }}
                        />
                      ))}
                    </div>
                  )}
                </div>
                {props.canPost && (
                  <button className={styles.witnessBtn} title="Witness this" onClick={() => setWitnessFor(m)}>
                    <Icon name="check" size={14} />
                  </button>
                )}
              </div>
            );
          })}
          {thinkingAgents.length > 0 && (
            <div className={styles.thinking}>
              <Avatar name={thinkingAgents[0]!} size="sm" isAgent />
              <span>
                {thinkingAgents.join(", ")} {thinkingAgents.length === 1 ? "is" : "are"} replying…
              </span>
            </div>
          )}
        </div>

        {props.canPost ? (
          <div className={styles.composer}>
            {pending.length > 0 && (
              <div className={styles.pending}>
                {pending.map((p) => (
                  <span key={p.id} className={styles.pendChip}>
                    <Icon name="paperclip" size={11} /> {p.name}
                    <button className={styles.pendX} onClick={() => setPending((x) => x.filter((y) => y.id !== p.id))} aria-label={`Remove ${p.name}`}>
                      <Icon name="x" size={10} />
                    </button>
                  </span>
                ))}
              </div>
            )}
            {mq !== null && suggestions.length > 0 && (
              <div className={styles.mentionPop} role="listbox">
                {suggestions.map((sg, i) => (
                  <button
                    key={sg.sub}
                    role="option"
                    aria-selected={i === mIdx}
                    className={`${styles.mentionItem} ${i === mIdx ? styles.mentionActive : ""}`}
                    onMouseDown={(e) => {
                      e.preventDefault();
                      applyMention(sg);
                    }}
                  >
                    <Avatar name={sg.name} size="sm" isAgent={sg.kind === "agent"} />
                    <span className={styles.mentionName}>{sg.name}</span>
                    {sg.kind === "agent" && <SurfBadge variant="agent">AGENT</SurfBadge>}
                    <span className={styles.mentionHandle}>@{sg.handle}</span>
                  </button>
                ))}
              </div>
            )}
            <textarea
              ref={inputRef}
              className={styles.input}
              placeholder={`Message #${props.channelName} — @ to mention a teammate or agent`}
              value={draft}
              onChange={(e) => {
                setDraft(e.target.value);
                syncMention(e.target.value, e.target.selectionStart);
              }}
              onKeyDown={(e) => {
                if (mq !== null && suggestions.length > 0) {
                  if (e.key === "ArrowDown") {
                    e.preventDefault();
                    setMIdx((i) => (i + 1) % suggestions.length);
                    return;
                  }
                  if (e.key === "ArrowUp") {
                    e.preventDefault();
                    setMIdx((i) => (i - 1 + suggestions.length) % suggestions.length);
                    return;
                  }
                  if (e.key === "Enter" || e.key === "Tab") {
                    e.preventDefault();
                    applyMention(suggestions[mIdx]!);
                    return;
                  }
                  if (e.key === "Escape") {
                    e.preventDefault();
                    setMq(null);
                    return;
                  }
                }
                if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                  e.preventDefault();
                  send();
                }
              }}
              rows={1}
            />
            <div className={styles.composerBar}>
              <ComposerAttach workspaceId={props.workspaceId} scope={{ channelId: props.channelId }} onAttached={(d) => setPending((p) => [...p, d])} />
              <SurfBadge variant="e2e">Encrypted</SurfBadge>
              <Btn variant="primary" size="sm" icon="send" onClick={send} disabled={sending || (!draft.trim() && pending.length === 0)}>
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
