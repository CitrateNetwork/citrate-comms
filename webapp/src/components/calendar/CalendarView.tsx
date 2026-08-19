"use client";

/**
 * CalendarView (CAL-1) — the team calendar surface.
 *
 * Two modes: a chronological **agenda** (default) and a traditional **month** grid,
 * toggled in the header. Everything renders in the *viewer's* timezone (detected from
 * the browser via Intl and shown prominently); the detected zone is saved to the member
 * profile so scheduling/reminders/emails use it. Meetings render in the accent color;
 * **deadlines render in red** with a RACI role badge. Members can create/edit/cancel
 * events and RSVP. Times are stored UTC server-side; this component converts for display
 * and converts local form input back to UTC on save.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Btn, Icon, Avatar } from "@/components/primitives";
import type { CalendarEvent, RaciRole } from "@/lib/domain/calendar";
import styles from "./CalendarView.module.css";

interface Props {
  workspaceId: string;
  meSub: string;
  canEdit: boolean;
  members: { sub: string; name: string }[];
  nameBySub: Record<string, string>;
  initialEvents: CalendarEvent[];
  initialFrom: string;
  initialTo: string;
}

type ViewMode = "agenda" | "month";

const RACI_LABEL: Record<RaciRole, string> = { R: "Responsible", A: "Accountable", C: "Consulted", I: "Informed" };

// ── timezone-aware formatting (viewer's browser zone) ────────────────────────
function browserTz(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}
function tzAbbr(tz: string): string {
  try {
    const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "short" }).formatToParts(new Date());
    return parts.find((p) => p.type === "timeZoneName")?.value ?? "";
  } catch {
    return "";
  }
}
function fmtTime(iso: string, tz: string): string {
  return new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "numeric", minute: "2-digit" }).format(new Date(iso));
}
function fmtDayLabel(iso: string, tz: string): string {
  return new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short", month: "short", day: "numeric" }).format(new Date(iso));
}
/** YYYY-MM-DD for an instant in a given tz (day-bucketing key). */
function dayKey(iso: string, tz: string): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(iso));
}
function todayKey(tz: string): string {
  return dayKey(new Date().toISOString(), tz);
}
/** Convert a <input type="datetime-local"> value (assumed in the viewer tz == browser
 *  local) to a UTC ISO string. */
function localInputToISO(v: string): string {
  return new Date(v).toISOString();
}
/** ISO → value for <input type="datetime-local"> in browser-local time. */
function isoToLocalInput(iso: string): string {
  const d = new Date(iso);
  const off = d.getTimezoneOffset();
  return new Date(d.getTime() - off * 60_000).toISOString().slice(0, 16);
}

export function CalendarView({ workspaceId, meSub, canEdit, members, nameBySub, initialEvents, initialFrom, initialTo }: Props) {
  const router = useRouter();
  const [tz, setTz] = useState<string>("UTC");
  const [view, setView] = useState<ViewMode>("agenda");
  const [anchor, setAnchor] = useState<Date>(() => new Date());
  const [events, setEvents] = useState<CalendarEvent[]>(initialEvents);
  const [loaded, setLoaded] = useState<{ from: string; to: string }>({ from: initialFrom, to: initialTo });
  const [showCreate, setShowCreate] = useState(false);
  const [detail, setDetail] = useState<CalendarEvent | null>(null);

  // Detect the browser timezone; persist it to the profile (fire-and-forget) so
  // scheduling/reminders/emails use it too.
  useEffect(() => {
    const z = browserTz();
    setTz(z);
    void fetch(`/api/workspaces/${workspaceId}/profile`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ timezone: z }),
    }).catch(() => {});
  }, [workspaceId]);

  // Visible range for the current view/anchor.
  const range = useMemo(() => {
    if (view === "agenda") {
      const from = new Date(anchor);
      from.setHours(0, 0, 0, 0);
      const to = new Date(from.getTime() + 30 * 86400_000);
      return { from, to };
    }
    // month grid: full weeks covering the anchor's month
    const first = new Date(anchor.getFullYear(), anchor.getMonth(), 1);
    const gridStart = new Date(first);
    gridStart.setDate(1 - first.getDay());
    const gridEnd = new Date(gridStart.getTime() + 42 * 86400_000);
    return { from: gridStart, to: gridEnd };
  }, [view, anchor]);

  // Fetch events whenever the visible range extends beyond what we've loaded.
  const loadRange = useCallback(
    async (from: string, to: string) => {
      try {
        const r = await fetch(`/api/workspaces/${workspaceId}/calendar?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`, { cache: "no-store" });
        if (!r.ok) return;
        const { events: fresh } = (await r.json()) as { events: CalendarEvent[] };
        setEvents(fresh);
        setLoaded({ from, to });
      } catch {
        /* keep prior events */
      }
    },
    [workspaceId],
  );

  useEffect(() => {
    const needFrom = range.from.toISOString();
    const needTo = range.to.toISOString();
    if (needFrom < loaded.from || needTo > loaded.to) void loadRange(needFrom, needTo);
  }, [range, loaded, loadRange]);

  const refresh = useCallback(() => void loadRange(range.from.toISOString(), range.to.toISOString()), [loadRange, range]);

  // Events visible in the current range, chronological.
  const visible = useMemo(() => {
    const f = range.from.getTime();
    const t = range.to.getTime();
    return events
      .filter((e) => new Date(e.endsAt).getTime() >= f && new Date(e.startsAt).getTime() <= t)
      .sort((a, b) => new Date(a.startsAt).getTime() - new Date(b.startsAt).getTime());
  }, [events, range]);

  const periodLabel =
    view === "month"
      ? new Intl.DateTimeFormat("en-US", { month: "long", year: "numeric" }).format(anchor)
      : `${new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(range.from)} – ${new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(new Date(range.to.getTime() - 86400_000))}`;

  function shift(dir: -1 | 1) {
    if (view === "month") setAnchor(new Date(anchor.getFullYear(), anchor.getMonth() + dir, 1));
    else setAnchor(new Date(anchor.getTime() + dir * 7 * 86400_000));
  }

  return (
    <div className={styles.wrap}>
      <header className={styles.head}>
        <div className={styles.headLeft}>
          <h1 className={styles.title}>Calendar</h1>
          <span className={styles.tz} title="Your timezone (from this device)">
            <Icon name="globe" size={13} /> {tz.replace(/_/g, " ")} {tzAbbr(tz) && `· ${tzAbbr(tz)}`}
          </span>
        </div>
        <div className={styles.headRight}>
          <div className={styles.toggle} role="tablist" aria-label="Calendar view">
            <button role="tab" aria-selected={view === "agenda"} className={view === "agenda" ? styles.toggleOn : styles.toggleOff} onClick={() => setView("agenda")}>
              <Icon name="projects" size={14} /> Agenda
            </button>
            <button role="tab" aria-selected={view === "month"} className={view === "month" ? styles.toggleOn : styles.toggleOff} onClick={() => setView("month")}>
              <Icon name="calendar" size={14} /> Month
            </button>
          </div>
          {canEdit && (
            <Btn variant="primary" icon="plus" onClick={() => setShowCreate(true)}>
              New event
            </Btn>
          )}
        </div>
      </header>

      <div className={styles.navbar}>
        <Btn variant="quiet" size="sm" onClick={() => setAnchor(new Date())}>
          Today
        </Btn>
        <button className={styles.navArrow} aria-label="Previous" onClick={() => shift(-1)}>
          <Icon name="chevR" size={16} style={{ transform: "rotate(180deg)" }} />
        </button>
        <button className={styles.navArrow} aria-label="Next" onClick={() => shift(1)}>
          <Icon name="chevR" size={16} />
        </button>
        <span className={styles.period}>{periodLabel}</span>
      </div>

      {view === "agenda" ? (
        <AgendaView events={visible} tz={tz} meSub={meSub} nameBySub={nameBySub} onOpen={setDetail} />
      ) : (
        <MonthView anchor={anchor} events={visible} tz={tz} onOpen={setDetail} />
      )}

      {showCreate && (
        <EventModal
          mode="create"
          workspaceId={workspaceId}
          tz={tz}
          members={members}
          meSub={meSub}
          onClose={() => setShowCreate(false)}
          onSaved={() => {
            setShowCreate(false);
            refresh();
            router.refresh();
          }}
        />
      )}
      {detail && (
        <EventModal
          mode="view"
          workspaceId={workspaceId}
          tz={tz}
          members={members}
          meSub={meSub}
          nameBySub={nameBySub}
          canEdit={canEdit}
          event={detail}
          onClose={() => setDetail(null)}
          onSaved={() => {
            setDetail(null);
            refresh();
            router.refresh();
          }}
        />
      )}
    </div>
  );
}

// ── agenda (chronological) ───────────────────────────────────────────────────
function AgendaView({ events, tz, meSub, nameBySub, onOpen }: { events: CalendarEvent[]; tz: string; meSub: string; nameBySub: Record<string, string>; onOpen: (e: CalendarEvent) => void }) {
  const groups = useMemo(() => {
    const byDay = new Map<string, CalendarEvent[]>();
    for (const e of events) {
      const k = dayKey(e.startsAt, tz);
      const list = byDay.get(k) ?? [];
      list.push(e);
      byDay.set(k, list);
    }
    return [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [events, tz]);

  if (groups.length === 0) return <div className={styles.empty}>Nothing scheduled in this range. Create an event to get started.</div>;
  const today = todayKey(tz);

  return (
    <div className={styles.agenda}>
      {groups.map(([key, list]) => (
        <div key={key} className={styles.agendaDay}>
          <div className={`${styles.agendaDate} ${key === today ? styles.isToday : ""}`}>
            {fmtDayLabel(list[0]!.startsAt, tz)}
            {key === today && <span className={styles.todayPill}>Today</span>}
          </div>
          <div className={styles.agendaList}>
            {list.map((e) => (
              <AgendaRow key={e.id} e={e} tz={tz} meSub={meSub} nameBySub={nameBySub} onOpen={onOpen} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function AgendaRow({ e, tz, meSub, nameBySub, onOpen }: { e: CalendarEvent; tz: string; meSub: string; nameBySub: Record<string, string>; onOpen: (e: CalendarEvent) => void }) {
  const isDeadline = e.kind === "deadline";
  const mine = e.attendees.find((a) => a.sub === meSub);
  return (
    <button className={`${styles.row} ${isDeadline ? styles.deadline : ""}`} onClick={() => onOpen(e)}>
      <span className={styles.rowTime}>{e.allDay ? "All day" : fmtTime(e.startsAt, tz)}</span>
      <span className={`${styles.rowBar} ${isDeadline ? styles.barRed : styles.barAccent}`} />
      <span className={styles.rowMain}>
        <span className={styles.rowTitle}>
          {isDeadline && <Icon name="clock" size={13} />} {e.title}
          {mine?.raciRole && <span className={`${styles.raci} ${isDeadline ? styles.raciRed : ""}`} title={RACI_LABEL[mine.raciRole]}>{mine.raciRole}</span>}
        </span>
        {e.location && <span className={styles.rowMeta}>{e.location}</span>}
      </span>
      <span className={styles.rowAtt}>
        {e.attendees.slice(0, 4).map((a) => (
          <Avatar key={a.sub} name={nameBySub[a.sub] ?? a.sub.slice(0, 6)} size="sm" />
        ))}
        {e.attendees.length > 4 && <span className={styles.more}>+{e.attendees.length - 4}</span>}
      </span>
    </button>
  );
}

// ── month grid (traditional) ─────────────────────────────────────────────────
function MonthView({ anchor, events, tz, onOpen }: { anchor: Date; events: CalendarEvent[]; tz: string; onOpen: (e: CalendarEvent) => void }) {
  const cells = useMemo(() => {
    const first = new Date(anchor.getFullYear(), anchor.getMonth(), 1);
    const start = new Date(first);
    start.setDate(1 - first.getDay());
    return Array.from({ length: 42 }, (_, i) => new Date(start.getTime() + i * 86400_000));
  }, [anchor]);

  const byDay = useMemo(() => {
    const m = new Map<string, CalendarEvent[]>();
    for (const e of events) {
      const k = dayKey(e.startsAt, tz);
      const list = m.get(k) ?? [];
      list.push(e);
      m.set(k, list);
    }
    return m;
  }, [events, tz]);

  const today = todayKey(tz);
  const month = anchor.getMonth();

  return (
    <div className={styles.month}>
      <div className={styles.weekHead}>
        {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d) => (
          <div key={d} className={styles.weekName}>
            {d}
          </div>
        ))}
      </div>
      <div className={styles.grid}>
        {cells.map((d) => {
          const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
          const list = byDay.get(k) ?? [];
          const outside = d.getMonth() !== month;
          return (
            <div key={k} className={`${styles.cell} ${outside ? styles.outside : ""} ${k === today ? styles.cellToday : ""}`}>
              <div className={styles.cellNum}>{d.getDate()}</div>
              <div className={styles.cellEvents}>
                {list.slice(0, 4).map((e) => (
                  <button key={e.id} className={`${styles.chip} ${e.kind === "deadline" ? styles.chipRed : ""}`} onClick={() => onOpen(e)} title={e.title}>
                    {!e.allDay && <span className={styles.chipTime}>{fmtTime(e.startsAt, tz)}</span>} {e.title}
                  </button>
                ))}
                {list.length > 4 && <span className={styles.moreDay}>+{list.length - 4} more</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── create / view / edit modal ───────────────────────────────────────────────
function EventModal(props: {
  mode: "create" | "view";
  workspaceId: string;
  tz: string;
  members: { sub: string; name: string }[];
  meSub: string;
  nameBySub?: Record<string, string>;
  canEdit?: boolean;
  event?: CalendarEvent;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { mode, workspaceId, tz, members, meSub, nameBySub = {}, canEdit = true, event, onClose, onSaved } = props;
  const editable = mode === "create" || (canEdit && event?.status !== "cancelled");
  const [editing, setEditing] = useState(mode === "create");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const now = new Date();
  const defaultStart = new Date(Math.ceil(now.getTime() / 3_600_000) * 3_600_000); // next hour
  const [title, setTitle] = useState(event?.title ?? "");
  const [kind, setKind] = useState<"meeting" | "deadline" | "focus">((event?.kind as "meeting" | "deadline" | "focus") ?? "meeting");
  const [start, setStart] = useState(isoToLocalInput(event?.startsAt ?? defaultStart.toISOString()));
  const [end, setEnd] = useState(isoToLocalInput(event?.endsAt ?? new Date(defaultStart.getTime() + 3_600_000).toISOString()));
  const [location, setLocation] = useState(event?.location ?? "");
  const [description, setDescription] = useState(event?.description ?? "");
  const [attendees, setAttendees] = useState<Record<string, RaciRole | "attendee">>(() => {
    const init: Record<string, RaciRole | "attendee"> = {};
    for (const a of event?.attendees ?? []) if (a.sub !== meSub) init[a.sub] = a.raciRole ?? "attendee";
    return init;
  });

  async function save() {
    setErr(null);
    if (!title.trim()) return setErr("Title is required");
    const startISO = localInputToISO(start);
    const endISO = localInputToISO(end);
    if (new Date(endISO) < new Date(startISO)) return setErr("End is before start");
    setBusy(true);
    try {
      const attList = Object.entries(attendees).map(([sub, role]) => ({ sub, raciRole: role === "attendee" ? null : role }));
      if (mode === "create") {
        const r = await fetch(`/api/workspaces/${workspaceId}/calendar`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ title: title.trim(), kind, startsAt: startISO, endsAt: endISO, timezone: tz, location: location || null, description: description || null, attendees: attList }),
        });
        if (!r.ok) throw new Error((await r.json().catch(() => ({})))?.error ?? "Could not create");
      } else if (event) {
        const r = await fetch(`/api/workspaces/${workspaceId}/calendar/${event.id}`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ title: title.trim(), startsAt: startISO, endsAt: endISO, timezone: tz, location: location || null, description: description || null }),
        });
        if (!r.ok) throw new Error("Could not save");
      }
      onSaved();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  }

  async function cancelEvt() {
    if (!event) return;
    setBusy(true);
    try {
      await fetch(`/api/workspaces/${workspaceId}/calendar/${event.id}`, { method: "DELETE" });
      onSaved();
    } catch {
      setBusy(false);
    }
  }

  async function rsvp(response: "accepted" | "declined" | "tentative") {
    if (!event) return;
    setBusy(true);
    try {
      await fetch(`/api/workspaces/${workspaceId}/calendar/${event.id}/rsvp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ response }),
      });
      onSaved();
    } catch {
      setBusy(false);
    }
  }

  const mine = event?.attendees.find((a) => a.sub === meSub);

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHead}>
          <h2>{mode === "create" ? "New event" : editing ? "Edit event" : title || "Event"}</h2>
          <button className={styles.close} aria-label="Close" onClick={onClose}>
            <Icon name="x" size={18} />
          </button>
        </div>

        {editing ? (
          <div className={styles.form}>
            <label className={styles.field}>
              <span>Title</span>
              <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus placeholder="Team sync, deadline, focus block…" />
            </label>
            <label className={styles.field}>
              <span>Type</span>
              <select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)} disabled={mode !== "create"}>
                <option value="meeting">Meeting</option>
                <option value="deadline">Deadline (red)</option>
                <option value="focus">Focus block</option>
              </select>
            </label>
            <div className={styles.row2}>
              <label className={styles.field}>
                <span>Start</span>
                <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
              </label>
              <label className={styles.field}>
                <span>End</span>
                <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
              </label>
            </div>
            <div className={styles.tzHint}>Times in {tz.replace(/_/g, " ")}</div>
            <label className={styles.field}>
              <span>Location</span>
              <input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="Room, call link, …" />
            </label>
            <label className={styles.field}>
              <span>Notes</span>
              <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
            </label>
            <div className={styles.field}>
              <span>People {kind === "deadline" ? "(RACI)" : "(attendees)"}</span>
              <div className={styles.people}>
                {members.filter((m) => m.sub !== meSub).map((m) => {
                  const cur = attendees[m.sub];
                  return (
                    <div key={m.sub} className={styles.person}>
                      <label className={styles.personName}>
                        <input
                          type="checkbox"
                          checked={cur !== undefined}
                          onChange={(e) => setAttendees((p) => { const n = { ...p }; if (e.target.checked) n[m.sub] = kind === "deadline" ? "R" : "attendee"; else delete n[m.sub]; return n; })}
                        />
                        {m.name}
                      </label>
                      {cur !== undefined && kind === "deadline" && (
                        <select value={cur} onChange={(e) => setAttendees((p) => ({ ...p, [m.sub]: e.target.value as RaciRole }))}>
                          <option value="R">R — Responsible</option>
                          <option value="A">A — Accountable</option>
                          <option value="C">C — Consulted</option>
                          <option value="I">I — Informed</option>
                        </select>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
            {err && <div className={styles.err}>{err}</div>}
            <div className={styles.actions}>
              {mode === "view" && <Btn variant="ghost" onClick={() => setEditing(false)} disabled={busy}>Cancel</Btn>}
              <Btn variant="primary" onClick={save} disabled={busy}>
                {busy ? "Saving…" : mode === "create" ? "Create event" : "Save"}
              </Btn>
            </div>
          </div>
        ) : (
          <div className={styles.detail}>
            <div className={`${styles.detailBar} ${event?.kind === "deadline" ? styles.barRed : styles.barAccent}`} />
            <div className={styles.detailBody}>
              <div className={styles.detailWhen}>
                <Icon name="clock" size={14} /> {event && fmtDayLabel(event.startsAt, tz)} · {event && fmtTime(event.startsAt, tz)}–{event && fmtTime(event.endsAt, tz)} <span className={styles.detailTz}>({tzAbbr(tz)})</span>
              </div>
              {event?.status === "cancelled" && <div className={styles.cancelled}>Cancelled</div>}
              {event?.location && <div className={styles.detailMeta}><Icon name="globe" size={13} /> {event.location}</div>}
              {event?.description && <p className={styles.detailNotes}>{event.description}</p>}
              {event && event.attendees.length > 0 && (
                <div className={styles.detailPeople}>
                  {event.attendees.map((a) => (
                    <span key={a.sub} className={styles.detailPerson}>
                      <Avatar name={nameBySub[a.sub] ?? a.sub.slice(0, 6)} size="sm" />
                      {nameBySub[a.sub] ?? a.sub.slice(0, 6)}
                      {a.raciRole && <span className={`${styles.raci} ${event.kind === "deadline" ? styles.raciRed : ""}`}>{a.raciRole}</span>}
                      {a.response === "accepted" && <Icon name="check" size={12} />}
                      {a.response === "declined" && <Icon name="x" size={12} />}
                    </span>
                  ))}
                </div>
              )}
              {mine && event?.status !== "cancelled" && (
                <div className={styles.rsvp}>
                  <span>Your RSVP:</span>
                  <Btn size="sm" variant={mine.response === "accepted" ? "primary" : "ghost"} onClick={() => rsvp("accepted")} disabled={busy}>Yes</Btn>
                  <Btn size="sm" variant={mine.response === "tentative" ? "primary" : "ghost"} onClick={() => rsvp("tentative")} disabled={busy}>Maybe</Btn>
                  <Btn size="sm" variant={mine.response === "declined" ? "danger" : "ghost"} onClick={() => rsvp("declined")} disabled={busy}>No</Btn>
                </div>
              )}
              {editable && event?.status !== "cancelled" && (
                <div className={styles.actions}>
                  <Btn variant="danger" icon="x" onClick={cancelEvt} disabled={busy}>Cancel event</Btn>
                  <Btn variant="ghost" onClick={() => setEditing(true)} disabled={busy}>Edit</Btn>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
