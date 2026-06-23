/**
 * The knowledge-graph seam (COMMS-AGENTS decision #4, build-spec §6).
 *
 * ONE interface, TWO backends:
 *  - GatewayMemoryStore — HTTP to `mem-gateway` (the federated graph, per-Org isolation,
 *    two-plane provenance, trust tiers). PRIMARY when reachable.
 *  - NeonMemoryStore   — a Neon-backed fallback (memory_nodes/_edges) implementing the
 *    SAME contract so recall+assert ship even if the gateway is down.
 *
 * `getMemoryStore()` picks the gateway when configured + healthy, else Neon. Either
 * way the agent code calls the same `recall/assert/verify/proposeEdge`.
 *
 * Recalled items carry a TRUST TIER (derived-deterministic › human-confirmed ›
 * agent-asserted › inferred-advisory) and provenance; the UI surfaces them as citations.
 * Agent writes land on the ASSERTED plane, signed (lib/security/crypto signWorkspace).
 */

export type TrustTier = "derived-deterministic" | "human-confirmed" | "agent-asserted" | "inferred-advisory";

/** Ordered strongest→weakest; index = rank (lower is more trusted). */
export const TRUST_ORDER: TrustTier[] = ["derived-deterministic", "human-confirmed", "agent-asserted", "inferred-advisory"];

export function trustRank(t: TrustTier): number {
  const i = TRUST_ORDER.indexOf(t);
  return i === -1 ? TRUST_ORDER.length : i;
}

/** A node passes the floor when it is at least as trusted as `floor`. */
export function meetsTrustFloor(tier: TrustTier, floor?: TrustTier): boolean {
  if (!floor) return true;
  return trustRank(tier) <= trustRank(floor);
}

export interface MemoryAnchor {
  entity: string; // account|deal|contact|channel|task|…
  id: string;
}

export interface MemoryNode {
  id: string;
  repo: string;
  plane: "asserted" | "derived";
  kind: string;
  content: string;
  anchors: MemoryAnchor[];
  trustTier: TrustTier;
  confidence: number; // 0..100
  signature?: string | null;
  validFrom?: string;
  status: "active" | "retracted";
}

export interface RecallQuery {
  query: string;
  anchors?: MemoryAnchor[];
  trustFloor?: TrustTier;
  budget?: number; // max items
  asOf?: string; // ISO instant for time-travel recall
}

export interface RecallResult {
  items: MemoryNode[];
  source: "gateway" | "neon";
}

export interface Verification {
  nodeId: string;
  signatureValid: boolean;
  trustTier: TrustTier;
  status: "active" | "retracted";
}

export interface AssertInput {
  kind: string;
  content: string;
  anchors?: MemoryAnchor[];
  confidence?: number; // 0..100
  trustTier?: TrustTier; // defaults to agent-asserted
}

export interface ProposeEdgeInput {
  from: string;
  to: string;
  kind: string;
  evidence?: string;
}

export interface MemoryEdge {
  id: string;
  from: string;
  to: string;
  kind: string;
  status: "quarantined" | "confirmed";
}

export interface MemoryStore {
  readonly source: "gateway" | "neon";
  recall(repo: string, q: RecallQuery): Promise<RecallResult>;
  verify(repo: string, nodeId: string): Promise<Verification | null>;
  assert(repo: string, node: AssertInput, by: { workspaceId: string; sub: string }): Promise<MemoryNode>;
  proposeEdge(repo: string, edge: ProposeEdgeInput, by: { workspaceId: string; sub: string }): Promise<MemoryEdge>;
}

/** Canonical repo id for a workspace's CRM memory. */
export function crmRepo(workspaceId: string): string {
  return `crm:${workspaceId}`;
}
