/**
 * NeonMemoryStore — the fallback knowledge-graph backend (decision #4). Implements
 * the MemoryStore contract over `memory_nodes`/`memory_edges`. Content is encrypted
 * per-workspace at rest; agent asserts are SIGNED (HMAC over the content hash, swap to
 * persona secp256k1 later) and land on the Asserted plane.
 *
 * Recall without embeddings (pgvector lands in S2): fetch a bounded window of recent
 * active nodes for the repo, decrypt, and rank by term-overlap with the query +
 * anchor match + trust tier. Honest and real — not a mock — just lexical until the
 * gateway/embeddings path is wired.
 */
import { blake3 } from "@noble/hashes/blake3";
import { bytesToHex } from "@noble/hashes/utils";
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { memoryNodes, memoryEdges } from "@/lib/db/schema";
import { encryptField, decryptField, signWorkspace, verifyWorkspaceSig } from "@/lib/security/crypto";
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
  meetsTrustFloor,
  trustRank,
} from "./store";

const RECALL_WINDOW = 500; // bounded scan until pgvector recall (S2)

function contentHash(repo: string, kind: string, content: string): string {
  return bytesToHex(blake3(new TextEncoder().encode(["comms/memory/v1", repo, kind, content].join("\n"))));
}

function tokens(s: string): Set<string> {
  return new Set(
    s
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 2),
  );
}

function overlapScore(query: Set<string>, content: string): number {
  if (query.size === 0) return 0;
  const c = tokens(content);
  let hits = 0;
  for (const q of query) if (c.has(q)) hits++;
  return hits / query.size;
}

function anchorMatch(want: MemoryAnchor[] | undefined, have: MemoryAnchor[]): number {
  if (!want || want.length === 0) return 0;
  const set = new Set(have.map((a) => `${a.entity}:${a.id}`));
  let hits = 0;
  for (const w of want) if (set.has(`${w.entity}:${w.id}`)) hits++;
  return hits;
}

export class NeonMemoryStore implements MemoryStore {
  readonly source = "neon" as const;

  async recall(repo: string, q: RecallQuery): Promise<RecallResult> {
    const workspaceId = repoWorkspace(repo);
    const rows = await db()
      .select()
      .from(memoryNodes)
      .where(and(eq(memoryNodes.workspaceId, workspaceId), eq(memoryNodes.repo, repo), eq(memoryNodes.status, "active")))
      .orderBy(desc(memoryNodes.validFrom))
      .limit(RECALL_WINDOW);

    const qTokens = tokens(q.query ?? "");
    const budget = Math.min(Math.max(q.budget ?? 6, 1), 50);

    const scored = rows
      .map((r) => {
        const content = safeDecrypt(workspaceId, r.contentEnc);
        const anchors = (r.anchorsJson as MemoryAnchor[] | null) ?? [];
        const tier = r.trustTier as TrustTier;
        const lexical = overlapScore(qTokens, content);
        const anchored = anchorMatch(q.anchors, anchors);
        // Rank: anchor matches dominate, then lexical, then trust (lower rank = better).
        const score = anchored * 10 + lexical * 4 + (3 - Math.min(trustRank(tier), 3)) * 0.25;
        return { node: toNode(r, content, anchors, tier), tier, score };
      })
      .filter((s) => meetsTrustFloor(s.tier, q.trustFloor))
      .filter((s) => qTokens.size === 0 || s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, budget);

    return { items: scored.map((s) => s.node), source: "neon" };
  }

  async verify(repo: string, nodeId: string): Promise<Verification | null> {
    const workspaceId = repoWorkspace(repo);
    const [r] = await db()
      .select()
      .from(memoryNodes)
      .where(and(eq(memoryNodes.workspaceId, workspaceId), eq(memoryNodes.id, nodeId)))
      .limit(1);
    if (!r) return null;
    const signatureValid = r.signature ? verifyWorkspaceSig(workspaceId, r.contentHash, r.signature) : false;
    return { nodeId, signatureValid, trustTier: r.trustTier as TrustTier, status: r.status as "active" | "retracted" };
  }

  async assert(repo: string, node: AssertInput, by: { workspaceId: string; sub: string }): Promise<MemoryNode> {
    const workspaceId = by.workspaceId;
    const hash = contentHash(repo, node.kind, node.content);
    const signature = signWorkspace(workspaceId, hash);
    const anchors = node.anchors ?? [];
    const tier: TrustTier = node.trustTier ?? "agent-asserted";
    const [r] = await db()
      .insert(memoryNodes)
      .values({
        workspaceId,
        repo,
        plane: "asserted",
        kind: node.kind,
        contentEnc: encryptField(workspaceId, node.content),
        anchorsJson: anchors,
        trustTier: tier,
        confidence: clampPct(node.confidence ?? 50),
        signature,
        contentHash: hash,
        createdBySub: by.sub,
      })
      .returning();
    return toNode(r!, node.content, anchors, tier);
  }

  async proposeEdge(repo: string, edge: ProposeEdgeInput, by: { workspaceId: string; sub: string }): Promise<MemoryEdge> {
    const workspaceId = by.workspaceId;
    const [r] = await db()
      .insert(memoryEdges)
      .values({
        workspaceId,
        repo,
        fromNode: edge.from,
        toNode: edge.to,
        kind: edge.kind,
        evidenceEnc: edge.evidence ? encryptField(workspaceId, edge.evidence) : null,
        status: "quarantined", // confirmed via a separate human/quorum step
        signature: signWorkspace(workspaceId, `${edge.from}->${edge.to}:${edge.kind}`),
        createdBySub: by.sub,
      })
      .returning();
    return { id: r!.id, from: r!.fromNode, to: r!.toNode, kind: r!.kind, status: r!.status as "quarantined" | "confirmed" };
  }
}

function toNode(
  r: typeof memoryNodes.$inferSelect,
  content: string,
  anchors: MemoryAnchor[],
  tier: TrustTier,
): MemoryNode {
  return {
    id: r.id,
    repo: r.repo,
    plane: r.plane as "asserted" | "derived",
    kind: r.kind,
    content,
    anchors,
    trustTier: tier,
    confidence: r.confidence,
    signature: r.signature,
    validFrom: r.validFrom?.toISOString(),
    status: r.status as "active" | "retracted",
  };
}

function safeDecrypt(workspaceId: string, packed: string): string {
  try {
    return decryptField(workspaceId, packed);
  } catch {
    return "";
  }
}

function clampPct(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** repo = `crm:<workspaceId>` — extract the workspace id (the bit after the first colon). */
function repoWorkspace(repo: string): string {
  const i = repo.indexOf(":");
  return i === -1 ? repo : repo.slice(i + 1);
}
