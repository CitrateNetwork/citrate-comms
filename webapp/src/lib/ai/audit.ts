/**
 * Tool-call transparency log + audit chaining (COMMS-AGENTS build-spec §4).
 *
 * `logToolCall` writes a row to `agent_tool_calls` BEFORE the tool executes —
 * truncated + key-scrubbed args plus a BLAKE3 hash of the full args — then appends a
 * `tool_called` record to the workspace BLAKE3 audit chain. `finishToolCall` records
 * the result hash after execution. Both are BEST-EFFORT: transparency logging must
 * NEVER break the agent (mirrors the explorer `logToolCall` no-throw contract), but
 * it also must never leak secrets — args are redacted before they are stored.
 */
import { blake3 } from "@noble/hashes/blake3";
import { bytesToHex } from "@noble/hashes/utils";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { agentToolCalls } from "@/lib/db/schema";
import { appendAudit } from "@/lib/audit/chain";

/** Keys whose VALUES must never be persisted (secrets/credentials/PII-ish). */
const SECRET_KEY = /(key|token|secret|password|passwd|authorization|auth|bearer|cgk|api[-_]?key|credential|cookie|session)/i;
const MAX_ARGS = 2000;

function hashArgs(args: unknown): string {
  return bytesToHex(blake3(new TextEncoder().encode(JSON.stringify(args ?? {}))));
}

/** Recursively scrub secret-looking values; truncate strings; cap depth/size. */
function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[…]";
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && value.length > 256) return value.slice(0, 256) + "…";
    return value;
  }
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SECRET_KEY.test(k) ? "[redacted]" : redact(v, depth + 1);
  }
  return out;
}

function redactedArgs(args: unknown): string {
  try {
    return JSON.stringify(redact(args)).slice(0, MAX_ARGS);
  } catch {
    return "[unserializable]";
  }
}

export interface ToolAuditCtx {
  workspaceId: string;
  threadId?: string | null;
  personaId?: string | null;
  invokedBySub?: string | null;
}

/**
 * Record a tool call before execution. Returns the row id (to attach a result hash),
 * or null if logging failed — the agent proceeds either way.
 */
export async function logToolCall(
  ctx: ToolAuditCtx,
  tool: string,
  args: unknown,
  approvalStatus: "auto" | "pending" | "approved" | "rejected" = "auto",
): Promise<string | null> {
  try {
    const [row] = await db()
      .insert(agentToolCalls)
      .values({
        workspaceId: ctx.workspaceId,
        threadId: ctx.threadId ?? null,
        personaId: ctx.personaId ?? null,
        invokedBySub: ctx.invokedBySub ?? null,
        tool,
        argsHash: hashArgs(args),
        argsRedacted: redactedArgs(args),
        approvalStatus,
      })
      .returning({ id: agentToolCalls.id });
    await appendAudit({
      workspaceId: ctx.workspaceId,
      actorSub: ctx.invokedBySub ?? null,
      event: "tool_called",
      target: `${tool}:${row?.id ?? ""}`,
    });
    return row?.id ?? null;
  } catch {
    // Swallow — transparency logging must never break the agent.
    return null;
  }
}

/** Record the result hash for a completed tool call (best-effort). */
export async function finishToolCall(id: string | null, result: unknown): Promise<void> {
  if (!id) return;
  try {
    await db()
      .update(agentToolCalls)
      .set({ resultHash: hashArgs(result) })
      .where(eq(agentToolCalls.id, id));
  } catch {
    /* best-effort */
  }
}

// Re-export the redaction for unit testing.
export const __test = { redact, redactedArgs, hashArgs };
