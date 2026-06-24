"use client";

/**
 * Agent panel — streaming chat with a persona (COMMS-AGENTS overview §3, build-spec §10).
 * Mirrors the citrate-explorer agent panel quality bar: token-aware streaming
 * (@ai-sdk/react useChat), a tool-trace (which tools ran + args + done), and citations
 * (memory items with trust tiers, CRM reads). Auth is the app's httpOnly session cookie
 * (same-origin fetch), so no Bearer wiring is needed. A client-stable conversation id is
 * sent as `threadId` so the server persists + resumes the thread.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { Avatar, Btn, Icon, SurfBadge } from "@/components/primitives";
import { ComposerAttach } from "@/components/attachments/ComposerAttach";
import { uploadAttachment, type UploadedDoc } from "@/components/attachments/uploadAttachment";
import { useFileDrop } from "@/components/attachments/useFileDrop";
import { Markdown } from "./Markdown";
import styles from "./AgentChat.module.css";

export interface PersonaOpt {
  id: string;
  name: string;
  key: string;
  tools?: string[];
}

/** Plain-English, honest descriptions of what each tool lets the agent do. */
const TOOL_LABEL: Record<string, string> = {
  "crm.read": "Read your CRM records",
  "crm.write": "Propose CRM edits (you approve)",
  "crm.note": "Propose notes on records (you approve)",
  "pm.read": "Read projects & tasks",
  "pm.write": "Propose tasks (you approve)",
  "ledger.write": "Propose witness-Ledger entries (you approve)",
  "thread.summarize": "Read a channel to summarize it",
  "memory.recall": "Recall from the knowledge graph",
  "memory.assert": "Propose graph findings (you approve)",
  "documents.read": "Search uploaded documents",
  "documents.write": "Propose new documents (you approve)",
  "documents.list": "List documents & artifacts",
  "artifact.attach": "Attach documents/images to its replies",
  "web.search": "Search the live web",
  "web.fetch": "Read a web page",
  "terminal.exec": "Run sandboxed commands (you approve)",
  "code.run": "Run sandboxed code (you approve)",
  "chart.render": "Render charts",
};

interface ChatMessage {
  id: string;
  role: string;
  parts?: { type: string; text?: string; toolName?: string; input?: unknown; output?: unknown; state?: string }[];
}

interface ToolStep {
  tool: string;
  args: string;
  done: boolean;
  citations: Citation[];
}
interface Citation {
  label: string;
  trustTier?: string;
  confidence?: number;
}

function newConvId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
  }
}

function textOf(m: ChatMessage): string {
  return (m.parts ?? [])
    .filter((p) => p.type === "text" && typeof p.text === "string")
    .map((p) => p.text as string)
    .join("");
}

/** Extract citations from a tool's output (memory.recall items, crm.read records). */
function citationsOf(tool: string, output: unknown): Citation[] {
  if (!output || typeof output !== "object") return [];
  const o = output as Record<string, unknown>;
  if (tool === "memory.recall" && Array.isArray(o.items)) {
    return (o.items as Record<string, unknown>[]).map((it) => ({
      label: String(it.content ?? it.kind ?? "memory"),
      trustTier: it.trustTier as string | undefined,
      confidence: it.confidence as number | undefined,
    }));
  }
  if (tool === "crm.read") {
    const rows = (o.accounts ?? o.deals ?? o.contacts) as Record<string, unknown>[] | undefined;
    if (Array.isArray(rows)) return rows.slice(0, 8).map((r) => ({ label: String(r.name ?? r.id ?? "record") }));
  }
  return [];
}

function toolStepsOf(m: ChatMessage): ToolStep[] {
  return (m.parts ?? [])
    .filter((p) => (typeof p.type === "string" && p.type.startsWith("tool-")) || p.type === "dynamic-tool")
    .map((p) => {
      const tool = p.type === "dynamic-tool" ? (p.toolName ?? "tool") : p.type.slice(5);
      const inp = (p.input ?? {}) as Record<string, unknown>;
      let args = "";
      try {
        args = Object.values(inp)
          .map((v) => (typeof v === "string" && v.length > 24 ? `${v.slice(0, 24)}…` : JSON.stringify(v)))
          .join(", ");
      } catch {
        /* ignore */
      }
      const done = p.state === "output-available" || p.state === "result";
      return { tool, args, done, citations: citationsOf(tool, p.output) };
    });
}

export function AgentChat({
  workspaceId,
  slug,
  persona,
  personas,
}: {
  workspaceId: string;
  slug: string;
  persona: PersonaOpt;
  personas: PersonaOpt[];
}) {
  const router = useRouter();
  const convIdRef = useRef<string>(newConvId());
  const [input, setInput] = useState("");
  const [incognito, setIncognito] = useState(false);
  const incognitoRef = useRef(false);
  useEffect(() => {
    incognitoRef.current = incognito;
  }, [incognito]);

  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: `/api/workspaces/${workspaceId}/agents/${persona.id}/chat`,
        body: () => ({ threadId: convIdRef.current, incognito: incognitoRef.current }),
      }),
    [workspaceId, persona.id],
  );

  const { messages, sendMessage, status, error, setMessages } = useChat({ transport });
  const busy = status === "submitted" || status === "streaming";
  const [showCaps, setShowCaps] = useState(false);

  // CH-0: conversation history (the caller's own threads for this persona) + resume.
  const [showHistory, setShowHistory] = useState(false);
  const [threads, setThreads] = useState<{ id: string; title: string; createdAt: string }[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  async function openHistory() {
    setShowHistory((v) => !v);
    if (threads.length > 0) return;
    setLoadingHistory(true);
    try {
      const r = await fetch(`/api/workspaces/${workspaceId}/agents/threads?personaId=${persona.id}`);
      const j = (await r.json()) as { threads?: { id: string; title: string; createdAt: string }[] };
      setThreads(j.threads ?? []);
    } catch {
      /* ignore */
    } finally {
      setLoadingHistory(false);
    }
  }

  async function resumeThread(threadId: string) {
    const r = await fetch(`/api/workspaces/${workspaceId}/agents/threads/${threadId}/messages`);
    if (!r.ok) return;
    const j = (await r.json()) as { messages?: { id: string; role: string; content: string }[] };
    const mapped = (j.messages ?? [])
      .filter((m) => m.role === "user" || m.role === "assistant")
      .map((m) => ({ id: m.id, role: m.role as "user" | "assistant", parts: [{ type: "text" as const, text: m.content }] }));
    convIdRef.current = threadId;
    setMessages(mapped as unknown as Parameters<typeof setMessages>[0]);
    setShowHistory(false);
  }

  function newChat() {
    convIdRef.current = newConvId();
    setMessages([]);
    setThreads([]); // refetch next open so the prior chat shows up
    setShowHistory(false);
  }

  // CH-2: toggling incognito always starts a clean session so a saved transcript and a
  // private one never share a window. Incognito turns are not persisted or audited and the
  // agent runs read-only (no write/approval tools).
  function toggleIncognito() {
    setIncognito((v) => !v);
    convIdRef.current = newConvId();
    setMessages([]);
    setShowHistory(false);
  }

  // Stick the transcript to the bottom while streaming, unless the user scrolled up.
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickRef = useRef(true);
  function onScroll() {
    const el = scrollRef.current;
    if (el) stickRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  }
  useEffect(() => {
    const el = scrollRef.current;
    if (el && stickRef.current) el.scrollTop = el.scrollHeight;
  }, [messages, status]);
  const list = messages as unknown as ChatMessage[];
  const lastId = list[list.length - 1]?.id;

  const [pendingAtts, setPendingAtts] = useState<UploadedDoc[]>([]);
  const [uploading, setUploading] = useState<string[]>([]); // names currently uploading
  const [attErr, setAttErr] = useState<string | null>(null);

  async function uploadFiles(fileList: File[]) {
    setAttErr(null);
    setUploading((u) => [...u, ...fileList.map((f) => f.name)]);
    for (const file of fileList) {
      const r = await uploadAttachment(workspaceId, {}, file);
      setUploading((u) => u.filter((n) => n !== file.name));
      if (r.ok) setPendingAtts((p) => [...p, r.doc]);
      else setAttErr(`${file.name}: ${r.error}`);
    }
  }
  const { dragging, dropProps } = useFileDrop(uploadFiles);

  function submit() {
    const t = input.trim();
    if ((!t && pendingAtts.length === 0) || busy) return;
    const note = pendingAtts.length ? `\n\n[Attached: ${pendingAtts.map((a) => a.name).join(", ")} — use documents.read to read them.]` : "";
    const text = (t + note).trim();
    if (!text) return;
    setInput("");
    setPendingAtts([]);
    sendMessage({ text });
  }

  return (
    <div className={styles.panel}>
      <header className={styles.head}>
        <div className={styles.headLeft}>
          <Avatar name={persona.name} size="md" isAgent />
          <div>
            <div className={styles.name}>
              {persona.name} <SurfBadge variant="agent">AGENT</SurfBadge>
            </div>
            <div className={styles.sub}>Audited · reads tools before it answers · writes are approval-gated</div>
          </div>
        </div>
        <div className={styles.headRight}>
          <button className={styles.capsBtn} onClick={newChat} title="Start a new conversation">
            <Icon name="plus" size={12} /> New
          </button>
          <button className={styles.capsBtn} onClick={openHistory} aria-expanded={showHistory} disabled={incognito}>
            <Icon name="clock" size={12} /> History
          </button>
          <button
            className={`${styles.capsBtn} ${incognito ? styles.capsBtnOn : ""}`}
            onClick={toggleIncognito}
            aria-pressed={incognito}
            title={incognito ? "Incognito on — this chat is not saved" : "Start a private, session-only chat"}
          >
            <Icon name="eye-off" size={12} /> Incognito
          </button>
          <button className={styles.capsBtn} onClick={() => setShowCaps((v) => !v)} aria-expanded={showCaps}>
            <Icon name="shield" size={12} /> What can it do?
          </button>
          {personas.length > 1 && (
            <select
              className={styles.picker}
              value={persona.id}
              onChange={(e) => router.push(`/w/${slug}/agents/${e.target.value}`)}
              aria-label="Switch persona"
            >
              {personas.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          )}
        </div>
      </header>

      {incognito && (
        <div className={styles.incognitoBar}>
          <Icon name="eye-off" size={12} /> Incognito — this conversation is not saved, not audited, and {persona.name} runs
          read-only (no writes or approvals). It ends when you leave or turn incognito off.
        </div>
      )}

      {showCaps && (
        <div className={styles.caps}>
          <div className={styles.capsTitle}>What {persona.name} can do</div>
          {(persona.tools ?? []).length > 0 ? (
            <ul className={styles.capsList}>
              {(persona.tools ?? []).map((t) => (
                <li key={t}>{TOOL_LABEL[t] ?? t}</li>
              ))}
            </ul>
          ) : (
            <div className={styles.capsNote}>This persona has no tools enabled yet.</div>
          )}
          <div className={styles.capsNote}>
            Every action is written to the audit trail. It reads with tools before it answers, and any write or
            sandbox action is queued for your approval — it can’t change records or membership on its own.
          </div>
        </div>
      )}

      {showHistory && (
        <div className={styles.caps}>
          <div className={styles.capsTitle}>Your conversations with {persona.name}</div>
          {loadingHistory ? (
            <div className={styles.capsNote}>Loading…</div>
          ) : threads.length === 0 ? (
            <div className={styles.capsNote}>No past conversations yet.</div>
          ) : (
            <div className={styles.histList}>
              {threads.map((t) => (
                <button key={t.id} className={styles.histItem} onClick={() => resumeThread(t.id)}>
                  <span className={styles.histTitle}>{t.title}</span>
                  <span className={styles.histWhen}>{new Date(t.createdAt).toLocaleDateString()}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div className={styles.scroll} ref={scrollRef} onScroll={onScroll}>
        {list.length === 0 && (
          <div className={styles.empty}>
            <p>Ask {persona.name} about your accounts, deals, or what it remembers.</p>
            <div className={styles.seeds}>
              {["Summarize the pipeline", "What deals are in Proposal?", "What do we know about our top account?"].map((q) => (
                <button key={q} className={styles.seed} onClick={() => sendMessage({ text: q })} disabled={busy}>
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {list.map((m) => {
          if (m.role === "user") {
            return (
              <div className={`${styles.msg} ${styles.user}`} key={m.id}>
                <div className={styles.bubble}>{textOf(m)}</div>
              </div>
            );
          }
          const steps = toolStepsOf(m);
          const text = textOf(m);
          const streamingThis = busy && m.id === lastId;
          const citations = steps.flatMap((s) => s.citations);
          return (
            <div className={`${styles.msg} ${styles.assistant}`} key={m.id}>
              {(steps.length > 0 || (streamingThis && !text)) && (
                <div className={styles.trace}>
                  <div className={styles.traceHead}>
                    <Icon name="audit" size={12} /> tool trace · audited
                  </div>
                  {steps.map((s, i) => (
                    <div className={styles.traceStep} key={i}>
                      <span className={styles.tool}>{s.tool}</span>
                      <span className={styles.args}>({s.args})</span>
                      {s.done ? <Icon name="check" size={12} /> : <span className={styles.dots}><i /><i /><i /></span>}
                    </div>
                  ))}
                  {streamingThis && steps.every((s) => s.done) && !text && (
                    <div className={styles.traceStep}>
                      <span className={styles.dots}><i /><i /><i /></span>
                      <span className={styles.note}>thinking…</span>
                    </div>
                  )}
                </div>
              )}
              {text && (
                <div className={styles.bubble}>
                  <Markdown>{text}</Markdown>
                  {citations.length > 0 && (
                    <div className={styles.citations}>
                      <div className={styles.citLbl}>Sources · what it read</div>
                      {citations.map((c, i) => (
                        <div className={styles.cit} key={i}>
                          <Icon name="check" size={11} />
                          <span className={styles.citText}>{c.label}</span>
                          {c.trustTier && (
                            <span className={styles.tier}>
                              {c.trustTier}
                              {c.confidence != null ? ` · ${c.confidence}%` : ""}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {!text && !steps.length && streamingThis && (
                <div className={styles.bubble}>
                  <span className={styles.dots}><i /><i /><i /></span>
                </div>
              )}
            </div>
          );
        })}

        {error && <div className={styles.err}>The agent hit an error. Please try again.</div>}
      </div>

      <div className={`${styles.composerWrap} ${dragging ? styles.dropping : ""}`} {...dropProps}>
        {dragging && <div className={styles.dropHint}>Drop files to attach</div>}
        {(pendingAtts.length > 0 || uploading.length > 0) && (
          <div className={styles.pending}>
            {pendingAtts.map((p) => (
              <span key={p.id} className={styles.pendChip}>
                <Icon name="paperclip" size={11} /> {p.name}
                <button className={styles.pendX} onClick={() => setPendingAtts((x) => x.filter((y) => y.id !== p.id))} aria-label={`Remove ${p.name}`}>
                  <Icon name="x" size={10} />
                </button>
              </span>
            ))}
            {uploading.map((n) => (
              <span key={`up-${n}`} className={`${styles.pendChip} ${styles.pendUploading}`}>
                <span className={styles.dots}><i /><i /><i /></span> {n}
              </span>
            ))}
          </div>
        )}
        {attErr && <div className={styles.attErr}>{attErr}</div>}
        <div className={styles.composer}>
          <ComposerAttach workspaceId={workspaceId} scope={{}} onAttached={(d) => setPendingAtts((p) => [...p, d])} onError={setAttErr} />
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                submit();
              }
            }}
            placeholder={`Message ${persona.name}…`}
            rows={2}
          />
          <Btn variant="primary" icon="send" onClick={submit} disabled={busy || (!input.trim() && pendingAtts.length === 0)}>
            {busy ? "…" : "Send"}
          </Btn>
        </div>
      </div>
    </div>
  );
}
