/**
 * GatewayMemoryStore — the PRIMARY knowledge-graph backend: HTTP to `mem-gateway`
 * (citrate-memories), which owns the federated two-plane graph, per-Org isolation,
 * trust tiers, and signed asserts. Mirrors the `mem-mcp` tool shapes
 * (recall/search/verify/assert/propose_edge).
 *
 * Auth: a per-workspace capability/OIDC token (MEM_GATEWAY_TOKEN for S0; minted
 * per-workspace later). Reachability is an open dependency — `getMemoryStore()`
 * health-probes and falls back to Neon, so the feature ships either way.
 *
 * NOTE: the exact mem-gateway HTTP surface is confirmed at wire-up; this client uses
 * the documented REST shape and is defensive about the response envelope.
 */
import {
  type MemoryStore,
  type RecallQuery,
  type RecallResult,
  type MemoryNode,
  type AssertInput,
  type ProposeEdgeInput,
  type MemoryEdge,
  type Verification,
  type TrustTier,
  type MemoryAnchor,
} from "./store";

const TIMEOUT_MS = 8000;

function baseUrl(): string | null {
  const u = process.env.MEM_GATEWAY_URL;
  return u ? u.replace(/\/$/, "") : null;
}
function token(): string | undefined {
  return process.env.MEM_GATEWAY_TOKEN;
}

async function call<T>(path: string, body: unknown): Promise<T> {
  const url = baseUrl();
  if (!url) throw new Error("MEM_GATEWAY_URL not set");
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(`${url}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token() ? { authorization: `Bearer ${token()}` } : {}),
      },
      body: JSON.stringify(body),
      cache: "no-store",
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`mem-gateway ${path} → ${r.status}`);
    return (await r.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

/** Probe the gateway; true only if it answers a health check quickly. */
export async function gatewayHealthy(): Promise<boolean> {
  const url = baseUrl();
  if (!url) return false;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 2500);
  try {
    const r = await fetch(`${url}/health`, {
      headers: token() ? { authorization: `Bearer ${token()}` } : {},
      cache: "no-store",
      signal: ac.signal,
    });
    return r.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

interface WireNode {
  id: string;
  repo?: string;
  plane?: string;
  kind: string;
  content: string;
  anchors?: MemoryAnchor[];
  trust_tier?: string;
  trustTier?: string;
  confidence?: number;
  signature?: string | null;
  valid_from?: string;
  status?: string;
}

function fromWire(repo: string, w: WireNode): MemoryNode {
  return {
    id: w.id,
    repo: w.repo ?? repo,
    plane: (w.plane as "asserted" | "derived") ?? "asserted",
    kind: w.kind,
    content: w.content,
    anchors: w.anchors ?? [],
    trustTier: (w.trust_tier ?? w.trustTier ?? "agent-asserted") as TrustTier,
    confidence: w.confidence ?? 50,
    signature: w.signature ?? null,
    validFrom: w.valid_from,
    status: (w.status as "active" | "retracted") ?? "active",
  };
}

export class GatewayMemoryStore implements MemoryStore {
  readonly source = "gateway" as const;

  async recall(repo: string, q: RecallQuery): Promise<RecallResult> {
    const res = await call<{ items?: WireNode[]; nodes?: WireNode[] }>("/recall", {
      repo,
      query: q.query,
      anchors: q.anchors,
      trust_floor: q.trustFloor,
      budget: q.budget ?? 6,
      as_of: q.asOf,
    });
    const items = (res.items ?? res.nodes ?? []).map((w) => fromWire(repo, w));
    return { items, source: "gateway" };
  }

  async verify(repo: string, nodeId: string): Promise<Verification | null> {
    const res = await call<{ node_id?: string; signature_valid?: boolean; trust_tier?: string; status?: string }>(
      "/verify",
      { repo, node_id: nodeId },
    );
    return {
      nodeId,
      signatureValid: Boolean(res.signature_valid),
      trustTier: (res.trust_tier ?? "agent-asserted") as TrustTier,
      status: (res.status as "active" | "retracted") ?? "active",
    };
  }

  async assert(repo: string, node: AssertInput, by: { workspaceId: string; sub: string }): Promise<MemoryNode> {
    const res = await call<{ node?: WireNode } & WireNode>("/assert", {
      repo,
      kind: node.kind,
      content: node.content,
      anchors: node.anchors ?? [],
      confidence: node.confidence ?? 50,
      trust_tier: node.trustTier ?? "agent-asserted",
      plane: "asserted",
      by_sub: by.sub,
    });
    return fromWire(repo, res.node ?? res);
  }

  async proposeEdge(repo: string, edge: ProposeEdgeInput, by: { workspaceId: string; sub: string }): Promise<MemoryEdge> {
    const res = await call<{ id: string; from?: string; to?: string; kind?: string; status?: string }>("/propose_edge", {
      repo,
      from: edge.from,
      to: edge.to,
      kind: edge.kind,
      evidence: edge.evidence,
      by_sub: by.sub,
    });
    return {
      id: res.id,
      from: res.from ?? edge.from,
      to: res.to ?? edge.to,
      kind: res.kind ?? edge.kind,
      status: (res.status as "quarantined" | "confirmed") ?? "quarantined",
    };
  }
}
