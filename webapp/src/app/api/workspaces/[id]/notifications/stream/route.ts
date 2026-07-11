/**
 * E-5 WP-1 — SSE stream of notification events (kills the 20s poll latency).
 *
 * GET /api/workspaces/[id]/notifications/stream
 *
 * Auth is the EXACT same gauntlet as the sibling notifications routes:
 * requireMember = verifySession (401) → active membership (403). A GuardError
 * is returned as a plain JSON error BEFORE any stream bytes are written.
 *
 * Events (all metadata-only — never message bodies, see notify-events.ts):
 *   { type: "unread", unread }                       absolute snapshot
 *   { type: "notification", id, kind, actorName, … } new-ping metadata
 *
 * Push path: the in-process notify bus (same-instance writes arrive < 2s).
 * Reconciliation path: the stream re-checks the unread count every
 * RECONCILE_MS and pushes a snapshot when it changed — this covers writes that
 * happened on ANOTHER serverless instance, where the in-process bus can't
 * reach us. The client additionally falls back to the legacy 20s poll if SSE
 * dies entirely (NotifBell).
 */
import { requireMember } from "@/lib/tenant/guard";
import { errorResponse } from "@/lib/http";
import { unreadCount } from "@/lib/domain/notifications";
import { subscribeNotify, type NotifyEvent } from "@/lib/realtime/notify-events";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
/** Fluid-compute budget; the stream self-closes before it and EventSource reconnects. */
export const maxDuration = 300;

const RECONCILE_MS = 10_000;
const STREAM_LIFETIME_MS = 270_000;

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let ctx;
  try {
    ctx = await requireMember(req, id);
  } catch (e) {
    return errorResponse(e);
  }
  const { sub } = ctx;

  const encoder = new TextEncoder();
  let cleanup = () => {};

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      let lastUnread = -1;

      const write = (chunk: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(chunk));
        } catch {
          closed = true;
        }
      };
      const send = (event: NotifyEvent) => write(`data: ${JSON.stringify(event)}\n\n`);

      const unsubscribe = subscribeNotify(id, sub, (event) => {
        send(event);
        if (event.type === "unread") lastUnread = event.unread;
      });

      // Reconcile cross-instance writes + keep intermediaries from idling us out.
      const timer = setInterval(() => {
        void (async () => {
          try {
            const n = await unreadCount(id, sub);
            if (n !== lastUnread) {
              lastUnread = n;
              send({ type: "unread", unread: n });
            } else {
              write(`: ping\n\n`); // SSE comment heartbeat
            }
          } catch {
            /* transient — next tick retries */
          }
        })();
      }, RECONCILE_MS);

      // Self-close before the platform kills us; EventSource auto-reconnects.
      const lifetime = setTimeout(() => cleanup(), STREAM_LIFETIME_MS);

      cleanup = () => {
        if (closed) return;
        closed = true;
        unsubscribe();
        clearInterval(timer);
        clearTimeout(lifetime);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      req.signal.addEventListener("abort", cleanup);

      // Initial snapshot so the badge is correct the instant the stream opens.
      try {
        lastUnread = await unreadCount(id, sub);
        send({ type: "unread", unread: lastUnread });
      } catch {
        /* the reconcile tick will retry */
      }
    },
    cancel() {
      cleanup();
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
