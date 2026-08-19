/**
 * Calendar domain (CAL-1). A native, encrypted team calendar.
 *
 * Storage posture: start/end are UTC `timestamptz` (queryable/sortable ranges) plus the
 * IANA `timezone` the event was authored in; the UI renders in the *viewer's* timezone.
 * Title/description/location are field-encrypted per workspace. Everything is scoped by
 * `workspaceId`, and reads are scoped to events the caller is an attendee of (or created).
 *
 * This module is the single source of truth for both the human UI (calendar page) and the
 * @calendar agent's tools. External Google/Outlook sync (Phase 4) writes through the same
 * rows via the external_* columns.
 */
import { and, asc, eq, gte, inArray, lte, ne, or } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { calendarEvents, eventAttendees, eventReminders } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";

export type RaciRole = "R" | "A" | "C" | "I";
export type EventKind = "meeting" | "deadline" | "focus" | "external";
export type EventStatus = "confirmed" | "tentative" | "cancelled";
export type RsvpResponse = "needsAction" | "accepted" | "declined" | "tentative";

/** Default reminder offsets (minutes before start): 1 day + 1 hour. */
export const DEFAULT_REMINDER_OFFSETS_MIN = [1440, 60];

export interface EventAttendeeInput {
  sub: string;
  raciRole?: RaciRole | null;
}

export interface EventAttendee {
  sub: string;
  raciRole: RaciRole | null;
  response: RsvpResponse;
}

export interface CreateEventInput {
  workspaceId: string;
  createdBySub: string;
  kind?: EventKind;
  title: string;
  description?: string | null;
  location?: string | null;
  startsAt: string; // ISO (UTC)
  endsAt: string; // ISO (UTC)
  allDay?: boolean;
  timezone: string; // IANA tz the author scheduled in
  channelId?: string | null;
  projectId?: string | null;
  taskId?: string | null;
  dealId?: string | null;
  attendees?: EventAttendeeInput[];
  reminderOffsetsMin?: number[];
}

export interface CalendarEvent {
  id: string;
  kind: EventKind;
  title: string;
  description: string | null;
  location: string | null;
  startsAt: string; // ISO UTC
  endsAt: string; // ISO UTC
  allDay: boolean;
  timezone: string;
  status: EventStatus;
  channelId: string | null;
  projectId: string | null;
  taskId: string | null;
  dealId: string | null;
  createdBySub: string;
  attendees: EventAttendee[];
}

function dec(workspaceId: string, v: string | null): string | null {
  if (v == null) return null;
  try {
    return decryptField(workspaceId, v);
  } catch {
    return null; // never leak ciphertext / crash a listing on one bad row
  }
}

/** Create an event, its attendees (creator auto-added as organizer/R), and reminder rows. */
export async function createEvent(input: CreateEventInput): Promise<{ id: string }> {
  const start = new Date(input.startsAt);
  const end = new Date(input.endsAt);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) throw new Error("invalid start/end");
  if (end.getTime() < start.getTime()) throw new Error("end before start");

  const [row] = await db()
    .insert(calendarEvents)
    .values({
      workspaceId: input.workspaceId,
      kind: input.kind ?? "meeting",
      titleEnc: encryptField(input.workspaceId, input.title),
      descriptionEnc: input.description ? encryptField(input.workspaceId, input.description) : null,
      locationEnc: input.location ? encryptField(input.workspaceId, input.location) : null,
      startsAt: start,
      endsAt: end,
      allDay: input.allDay ?? false,
      timezone: input.timezone || "UTC",
      channelId: input.channelId ?? null,
      projectId: input.projectId ?? null,
      taskId: input.taskId ?? null,
      dealId: input.dealId ?? null,
      createdBySub: input.createdBySub,
    })
    .returning({ id: calendarEvents.id });
  const eventId = row!.id;

  // Attendees: de-dupe, always include the creator (organizer → Responsible, accepted).
  const byName = new Map<string, EventAttendeeInput>();
  byName.set(input.createdBySub, { sub: input.createdBySub, raciRole: "R" });
  for (const a of input.attendees ?? []) if (a.sub) byName.set(a.sub, a);
  const attendeeRows = [...byName.values()].map((a) => ({
    workspaceId: input.workspaceId,
    eventId,
    sub: a.sub,
    raciRole: a.raciRole ?? null,
    response: (a.sub === input.createdBySub ? "accepted" : "needsAction") as RsvpResponse,
  }));
  if (attendeeRows.length) await db().insert(eventAttendees).values(attendeeRows);

  await scheduleReminders(input.workspaceId, eventId, start, attendeeRows.map((a) => a.sub), input.reminderOffsetsMin);
  return { id: eventId };
}

/** (Re)create future reminder rows for an event's attendees. Idempotent-ish: clears the
 *  event's unsent reminders first so a reschedule re-times them. */
export async function scheduleReminders(
  workspaceId: string,
  eventId: string,
  startsAt: Date,
  subs: string[],
  offsetsMin: number[] = DEFAULT_REMINDER_OFFSETS_MIN,
): Promise<void> {
  await db().delete(eventReminders).where(and(eq(eventReminders.eventId, eventId), eq(eventReminders.workspaceId, workspaceId)));
  const now = Date.now();
  const rows: (typeof eventReminders.$inferInsert)[] = [];
  for (const sub of subs) {
    for (const off of offsetsMin) {
      const remindAt = new Date(startsAt.getTime() - off * 60_000);
      if (remindAt.getTime() > now) rows.push({ workspaceId, eventId, sub, remindAt, channel: "both" });
    }
  }
  if (rows.length) await db().insert(eventReminders).values(rows);
}

interface EventBaseRow {
  id: string;
  kind: string;
  titleEnc: string;
  descriptionEnc: string | null;
  locationEnc: string | null;
  startsAt: Date;
  endsAt: Date;
  allDay: boolean;
  timezone: string;
  status: string;
  channelId: string | null;
  projectId: string | null;
  taskId: string | null;
  dealId: string | null;
  createdBySub: string;
}

async function hydrate(workspaceId: string, rows: EventBaseRow[]): Promise<CalendarEvent[]> {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id);
  const atts = await db()
    .select({ eventId: eventAttendees.eventId, sub: eventAttendees.sub, raciRole: eventAttendees.raciRole, response: eventAttendees.response })
    .from(eventAttendees)
    .where(and(eq(eventAttendees.workspaceId, workspaceId), inArray(eventAttendees.eventId, ids)));
  const byEvent = new Map<string, EventAttendee[]>();
  for (const a of atts) {
    const list = byEvent.get(a.eventId) ?? [];
    list.push({ sub: a.sub, raciRole: (a.raciRole as RaciRole | null) ?? null, response: a.response as RsvpResponse });
    byEvent.set(a.eventId, list);
  }
  return rows.map((r) => ({
    id: r.id,
    kind: r.kind as EventKind,
    title: dec(workspaceId, r.titleEnc) ?? "(untitled)",
    description: dec(workspaceId, r.descriptionEnc),
    location: dec(workspaceId, r.locationEnc),
    startsAt: r.startsAt.toISOString(),
    endsAt: r.endsAt.toISOString(),
    allDay: r.allDay,
    timezone: r.timezone,
    status: r.status as EventStatus,
    channelId: r.channelId,
    projectId: r.projectId,
    taskId: r.taskId,
    dealId: r.dealId,
    createdBySub: r.createdBySub,
    attendees: byEvent.get(r.id) ?? [],
  }));
}

const BASE_COLS = {
  id: calendarEvents.id,
  kind: calendarEvents.kind,
  titleEnc: calendarEvents.titleEnc,
  descriptionEnc: calendarEvents.descriptionEnc,
  locationEnc: calendarEvents.locationEnc,
  startsAt: calendarEvents.startsAt,
  endsAt: calendarEvents.endsAt,
  allDay: calendarEvents.allDay,
  timezone: calendarEvents.timezone,
  status: calendarEvents.status,
  channelId: calendarEvents.channelId,
  projectId: calendarEvents.projectId,
  taskId: calendarEvents.taskId,
  dealId: calendarEvents.dealId,
  createdBySub: calendarEvents.createdBySub,
} as const;

/** Events overlapping [fromISO, toISO] that the member attends (or created). Cancelled
 *  events are excluded. Ordered chronologically. */
export async function listEventsInRange(workspaceId: string, sub: string, fromISO: string, toISO: string): Promise<CalendarEvent[]> {
  const from = new Date(fromISO);
  const to = new Date(toISO);
  const rows = await db()
    .selectDistinct(BASE_COLS)
    .from(calendarEvents)
    .leftJoin(eventAttendees, eq(eventAttendees.eventId, calendarEvents.id))
    .where(
      and(
        eq(calendarEvents.workspaceId, workspaceId),
        ne(calendarEvents.status, "cancelled"),
        // overlap: event starts before window end AND ends after window start
        lte(calendarEvents.startsAt, to),
        gte(calendarEvents.endsAt, from),
        or(eq(eventAttendees.sub, sub), eq(calendarEvents.createdBySub, sub)),
      ),
    )
    .orderBy(asc(calendarEvents.startsAt));
  return hydrate(workspaceId, rows);
}

/** A single event with attendees (workspace-scoped; caller membership checked upstream). */
export async function getEvent(workspaceId: string, eventId: string): Promise<CalendarEvent | null> {
  const rows = await db()
    .select(BASE_COLS)
    .from(calendarEvents)
    .where(and(eq(calendarEvents.workspaceId, workspaceId), eq(calendarEvents.id, eventId)))
    .limit(1);
  if (rows.length === 0) return null;
  return (await hydrate(workspaceId, rows))[0] ?? null;
}

export interface UpdateEventPatch {
  title?: string;
  description?: string | null;
  location?: string | null;
  startsAt?: string;
  endsAt?: string;
  allDay?: boolean;
  timezone?: string;
  status?: EventStatus;
}

/** Update event fields (re-encrypting changed text). Re-times reminders if start moves. */
export async function updateEvent(workspaceId: string, eventId: string, patch: UpdateEventPatch): Promise<void> {
  const set: Partial<typeof calendarEvents.$inferInsert> = { updatedAt: new Date() };
  if (patch.title !== undefined) set.titleEnc = encryptField(workspaceId, patch.title);
  if (patch.description !== undefined) set.descriptionEnc = patch.description ? encryptField(workspaceId, patch.description) : null;
  if (patch.location !== undefined) set.locationEnc = patch.location ? encryptField(workspaceId, patch.location) : null;
  if (patch.startsAt !== undefined) set.startsAt = new Date(patch.startsAt);
  if (patch.endsAt !== undefined) set.endsAt = new Date(patch.endsAt);
  if (patch.allDay !== undefined) set.allDay = patch.allDay;
  if (patch.timezone !== undefined) set.timezone = patch.timezone;
  if (patch.status !== undefined) set.status = patch.status;
  await db().update(calendarEvents).set(set).where(and(eq(calendarEvents.workspaceId, workspaceId), eq(calendarEvents.id, eventId)));

  if (patch.startsAt !== undefined) {
    const [ev] = await db().select({ startsAt: calendarEvents.startsAt }).from(calendarEvents).where(eq(calendarEvents.id, eventId)).limit(1);
    const subs = (await db().select({ sub: eventAttendees.sub }).from(eventAttendees).where(eq(eventAttendees.eventId, eventId))).map((a) => a.sub);
    if (ev) await scheduleReminders(workspaceId, eventId, ev.startsAt, subs);
  }
}

/** Cancel an event (soft — kept for history/audit; excluded from listings). */
export async function cancelEvent(workspaceId: string, eventId: string): Promise<void> {
  await db().update(calendarEvents).set({ status: "cancelled", updatedAt: new Date() }).where(and(eq(calendarEvents.workspaceId, workspaceId), eq(calendarEvents.id, eventId)));
  await db().delete(eventReminders).where(and(eq(eventReminders.workspaceId, workspaceId), eq(eventReminders.eventId, eventId)));
}

/** Set the caller's RSVP on an event. */
export async function setAttendeeResponse(workspaceId: string, eventId: string, sub: string, response: RsvpResponse): Promise<void> {
  await db()
    .update(eventAttendees)
    .set({ response })
    .where(and(eq(eventAttendees.workspaceId, workspaceId), eq(eventAttendees.eventId, eventId), eq(eventAttendees.sub, sub)));
}
