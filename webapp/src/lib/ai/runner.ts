/**
 * comms-agent-runner control-API client (COMMS-AGENTS S3). The runner is a hardened
 * Rust daemon co-located with the inference gateway (DGX/droplet) that runs the
 * PRIVILEGED tools — web search/fetch (keyed provider), terminal/code in a capsule
 * sandbox, chart render — with OS-keyring key custody it never returns to the BFF.
 *
 * The BFF orchestrates the loop and DELEGATES those tools here over an authenticated
 * HTTP/JSON control API (private network / Caddy-fronted; bearer auth). FAIL-CLOSED:
 * if the runner isn't configured/reachable, the delegating tools report "unavailable"
 * rather than pretending — and dangerous tools (terminal/code) are HITL-gated first.
 *
 * Env: COMMS_RUNNER_URL (e.g. http://127.0.0.1:8791 or the private Caddy host),
 *      COMMS_RUNNER_BEARER (per-instance secret). See the runner registration handoff.
 */
const TIMEOUT_MS = 30_000;

function config(): { url: string; bearer: string } | null {
  const url = process.env.COMMS_RUNNER_URL;
  const bearer = process.env.COMMS_RUNNER_BEARER;
  if (!url || !bearer) return null;
  return { url: url.replace(/\/$/, ""), bearer };
}

export function runnerConfigured(): boolean {
  return config() !== null;
}

export class RunnerUnavailableError extends Error {
  constructor(msg = "the agent runner is not configured or reachable") {
    super(msg);
    this.name = "RunnerUnavailableError";
  }
}

async function runnerCall<T>(path: string, body: unknown): Promise<T> {
  const cfg = config();
  if (!cfg) throw new RunnerUnavailableError();
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(`${cfg.url}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${cfg.bearer}` },
      body: JSON.stringify(body),
      cache: "no-store",
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`runner ${path} → ${r.status}`);
    return (await r.json()) as T;
  } catch (err) {
    if (err instanceof RunnerUnavailableError) throw err;
    throw new RunnerUnavailableError(`runner ${path} failed`);
  } finally {
    clearTimeout(timer);
  }
}

// ── Control-API surface (mirrors the runner contract, build-spec §9) ──────────

export interface WebResult {
  title: string;
  url: string;
  snippet: string;
}
export async function webSearch(query: string, k = 5): Promise<{ results: WebResult[] }> {
  return runnerCall("/tools/web-search", { query, k });
}
export async function webFetch(url: string): Promise<{ text: string; url: string }> {
  return runnerCall("/tools/web-fetch", { url });
}
export interface TerminalResult {
  stdout: string;
  stderr: string;
  exit: number;
  artifacts?: { name: string; url: string }[];
}
export async function terminalExec(cmd: string, cwd?: string, sandboxId?: string): Promise<TerminalResult> {
  return runnerCall("/tools/terminal", { cmd, cwd, sandbox_id: sandboxId });
}
export interface CodeResult {
  stdout: string;
  stderr?: string;
  artifacts?: { name: string; url: string }[];
}
export async function codeRun(lang: string, source: string, files?: { name: string; content: string }[]): Promise<CodeResult> {
  return runnerCall("/tools/code", { lang, source, files });
}
export async function chartRender(spec: unknown): Promise<{ url: string }> {
  return runnerCall("/tools/chart", { spec });
}
