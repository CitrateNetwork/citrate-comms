/**
 * citrate-comms web app — Neon Postgres schema (Drizzle).
 *
 * Mirrors the native domain model (`comms-proto`, `comms-core::domain`) but inverts
 * its storage posture: the native app keeps NO server-side DB (clients fold the MLS
 * event stream); the trusted-tier web app makes Neon the authoritative materialized
 * store and CAN read content. That is the honest "team-trusted vs server-blind"
 * boundary (surfaced in the UI).
 *
 * Invariants:
 *  - **Tenancy:** every domain table carries `workspaceId` NOT NULL, first in its
 *    indexes. A `requireMembership(workspaceId, sub)` guard + workspace-predicated
 *    queries enforce isolation (RLS migration staged as belt-and-suspenders).
 *  - **Owner key:** the canonical per-user key is the OIDC `sub`, NOT the wallet.
 *  - **Encryption:** columns ending `_enc` hold AES-256-GCM ciphertext (per-workspace
 *    key, lib/security/crypto.ts). The no-pii allow-list test asserts which columns
 *    may hold cleartext.
 *  - **Bridge-ready:** message/event rows carry the native MLS coordinates
 *    (`groupId`, `groupSeq`, `epoch`, `senderWallet`, `ciphertextHash`, `clientMsgId`,
 *    `onBehalfOf`) and an `outbox` exists from day one, so the comms-web-gateway can
 *    slot in without a schema change.
 */
import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  text,
  boolean,
  integer,
  bigint,
  bigserial,
  timestamp,
  jsonb,
  vector,
  index,
  primaryKey,
  uniqueIndex,
} from "drizzle-orm/pg-core";

/** Embedding width for the gateway bge model (bge-large / bge-m3 → 1024 dims). */
export const EMBEDDING_DIM = 1024;

// ── Tenancy & identity ──────────────────────────────────────────────────────

export const workspaces = pgTable("workspaces", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  ownerSub: text("owner_sub").notNull(), // OIDC sub of the creator/owner
  encKeyVersion: integer("enc_key_version").notNull().default(1),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** A member is a (workspace, identity) binding. identity = OIDC sub (canonical). */
export const members = pgTable(
  "members",
  {
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    sub: text("sub").notNull(), // canonical owner key (NOT wallet)
    walletAddress: text("wallet_address"), // lowercased; denormalized from claim
    displayName: text("display_name"),
    email: text("email"), // stored only when email_verified === true (FWA-C6-01)
    role: text("role").notNull(), // Owner|Admin|Member|Partner|Guest|Agent
    status: text("status").notNull().default("active"), // active|invited|suspended|offboarded
    kycStatus: text("kyc_status"),
    isAgent: boolean("is_agent").notNull().default(false),
    devicesCount: integer("devices_count").notNull().default(0),
    joinedAt: timestamp("joined_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.workspaceId, t.sub] }), index("members_ws_role").on(t.workspaceId, t.role)],
);

/** Signed role grants, mirrored for audit. The web tier mints them server-side;
 *  a wallet signature is optional in the trusted tier (present when a wallet co-signs). */
export const roleAssertions = pgTable(
  "role_assertions",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    subjectSub: text("subject_sub").notNull(),
    role: text("role").notNull(),
    scopeChannelId: uuid("scope_channel_id"), // NULL = workspace-wide
    issuerSub: text("issuer_sub").notNull(),
    notAfter: timestamp("not_after", { withTimezone: true }),
    signature: text("signature"), // secp256k1 hex if a wallet co-signs; else NULL
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("role_assertions_ws_subject").on(t.workspaceId, t.subjectSub)],
);

export const devices = pgTable(
  "devices",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    sub: text("sub").notNull(),
    label: text("label"),
    signingMethod: text("signing_method"), // passkey|google|password|siwe
    lastSeen: timestamp("last_seen", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("devices_ws_sub").on(t.workspaceId, t.sub)],
);

export const invites = pgTable(
  "invites",
  {
    tokenHash: text("token_hash").primaryKey(), // SHA-256(token); raw token never persisted
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    email: text("email").notNull(),
    role: text("role").notNull(),
    scopeChannelId: uuid("scope_channel_id"), // for Partner/Guest scoping
    invitedBySub: text("invited_by_sub").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedBySub: text("accepted_by_sub"),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("invites_ws").on(t.workspaceId)],
);

// ── Conversations ───────────────────────────────────────────────────────────

export const channels = pgTable(
  "channels",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    kind: text("kind").notNull(), // channel|forum|dm
    name: text("name").notNull(),
    topic: text("topic"),
    isStarred: boolean("is_starred").notNull().default(false),
    hasAgent: boolean("has_agent").notNull().default(false),
    // Bridge coordinates: the native MLS group this channel maps to (NULL until bridged).
    groupId: text("group_id"),
    bridged: boolean("bridged").notNull().default(false),
    createdBySub: text("created_by_sub").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("channels_ws_kind").on(t.workspaceId, t.kind)],
);

export const channelMembers = pgTable(
  "channel_members",
  {
    workspaceId: uuid("workspace_id").notNull(),
    channelId: uuid("channel_id").notNull().references(() => channels.id),
    sub: text("sub").notNull(),
    addedAt: timestamp("added_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.channelId, t.sub] }), index("channel_members_ws").on(t.workspaceId)],
);

export const messages = pgTable(
  "messages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    channelId: uuid("channel_id").notNull().references(() => channels.id),
    threadId: uuid("thread_id"),
    parentId: uuid("parent_id"),
    authorSub: text("author_sub").notNull(),
    fromAgent: boolean("from_agent").notNull().default(false),
    bodyEnc: text("body_enc").notNull(), // AES-256-GCM per-workspace
    state: text("state").notNull().default("sent"), // sent|edited|deleted
    seq: bigint("seq", { mode: "number" }).notNull(), // per-channel monotonic order (poll/SSE cursor)
    // Bridge coordinates (native MLS): set by the gateway, NULL for web-only rows pre-bridge.
    groupSeq: bigint("group_seq", { mode: "number" }),
    epoch: bigint("epoch", { mode: "number" }),
    senderWallet: text("sender_wallet"),
    ciphertextHash: text("ciphertext_hash"),
    clientMsgId: text("client_msg_id"), // outbound dedupe across the bridge
    onBehalfOf: text("on_behalf_of"), // real author when posted via the web gateway
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("messages_channel_seq").on(t.workspaceId, t.channelId, t.seq),
    index("messages_thread").on(t.workspaceId, t.threadId),
  ],
);

export const messageLinks = pgTable(
  "message_links",
  {
    messageId: uuid("message_id").notNull().references(() => messages.id),
    workspaceId: uuid("workspace_id").notNull(),
    entityType: text("entity_type").notNull(), // deal|task
    entityId: uuid("entity_id").notNull(),
  },
  (t) => [primaryKey({ columns: [t.messageId, t.entityType, t.entityId] })],
);

export const threads = pgTable(
  "threads",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    channelId: uuid("channel_id").notNull().references(() => channels.id),
    title: text("title").notNull(),
    authorSub: text("author_sub").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("threads_ws_channel").on(t.workspaceId, t.channelId)],
);

// ── The witness Ledger (signature feature) ──────────────────────────────────

export const ledgerEntries = pgTable(
  "ledger_entries",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    channelId: uuid("channel_id").notNull().references(() => channels.id),
    sourceMessageId: uuid("source_message_id").references(() => messages.id),
    kind: text("kind").notNull(), // decision|commitment|resolved
    textEnc: text("text_enc").notNull(),
    bySub: text("by_sub").notNull(), // attributed author
    ownerSub: text("owner_sub"),
    due: timestamp("due", { withTimezone: true }),
    status: text("status").notNull().default("open"), // open|done
    proposedByAgent: boolean("proposed_by_agent").notNull().default(false),
    recordHash: text("record_hash").notNull(), // links into the audit chain
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("ledger_ws_channel").on(t.workspaceId, t.channelId)],
);

// ── CRM (deals are children of accounts) ────────────────────────────────────

export const accounts = pgTable(
  "accounts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    name: text("name").notNull(),
    domain: text("domain"),
    ownerSub: text("owner_sub"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("accounts_ws").on(t.workspaceId)],
);

export const contacts = pgTable(
  "contacts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    accountId: uuid("account_id").references(() => accounts.id),
    name: text("name").notNull(),
    emailEnc: text("email_enc"),
    title: text("title"),
    ownerSub: text("owner_sub"),
    lastTouch: timestamp("last_touch", { withTimezone: true }),
  },
  (t) => [index("contacts_ws_account").on(t.workspaceId, t.accountId)],
);

export const deals = pgTable(
  "deals",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    accountId: uuid("account_id").references(() => accounts.id), // deals are CHILDREN of an account
    name: text("name").notNull(),
    valueMinor: bigint("value_minor", { mode: "number" }).notNull().default(0), // cents
    stage: text("stage").notNull().default("Lead"), // Lead|Qualified|Proposal|Won|Lost
    priority: text("priority"), // low|medium|high
    ownerSub: text("owner_sub"),
    closeDate: timestamp("close_date", { withTimezone: true }),
    linkedChannelId: uuid("linked_channel_id").references(() => channels.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("deals_ws_stage").on(t.workspaceId, t.stage), index("deals_ws_account").on(t.workspaceId, t.accountId)],
);

// ── Project management ──────────────────────────────────────────────────────

export const projects = pgTable(
  "projects",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    name: text("name").notNull(),
    status: text("status").notNull().default("active"), // active|paused|done
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("projects_ws").on(t.workspaceId)],
);

export const boards = pgTable(
  "boards",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    projectId: uuid("project_id").references(() => projects.id),
    name: text("name").notNull(),
  },
  (t) => [index("boards_ws_project").on(t.workspaceId, t.projectId)],
);

export const boardColumns = pgTable(
  "board_columns",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull(),
    boardId: uuid("board_id").notNull().references(() => boards.id),
    name: text("name").notNull(),
    ord: integer("ord").notNull().default(0),
  },
  (t) => [index("board_columns_ws_board").on(t.workspaceId, t.boardId)],
);

export const tasks = pgTable(
  "tasks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    projectId: uuid("project_id").references(() => projects.id),
    boardId: uuid("board_id"),
    columnId: uuid("column_id"),
    title: text("title").notNull(),
    description: text("description"),
    assigneeSub: text("assignee_sub"),
    status: text("status").notNull().default("Backlog"), // Backlog|Todo|InProgress|InReview|Done
    priority: text("priority"),
    due: timestamp("due", { withTimezone: true }),
    ord: integer("ord").notNull().default(0),
    linkedChannelId: uuid("linked_channel_id").references(() => channels.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("tasks_ws_status").on(t.workspaceId, t.status), index("tasks_ws_column").on(t.workspaceId, t.columnId)],
);

// ── Agents (agents-as-members) ──────────────────────────────────────────────

export const agents = pgTable(
  "agents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    memberSub: text("member_sub").notNull(), // FK to members(sub) with is_agent=true
    name: text("name").notNull(),
    purpose: text("purpose"),
    kind: text("kind"),
    status: text("status").notNull().default("active"), // active|paused
    sponsorSub: text("sponsor_sub"),
    config: jsonb("config"),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("agents_ws").on(t.workspaceId)],
);

// ── Audit hash-chain (BLAKE3, append-only, one chain per workspace) ──────────

export const auditLog = pgTable(
  "audit_log",
  {
    seq: bigserial("seq", { mode: "number" }).primaryKey(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    actorSub: text("actor_sub"),
    event: text("event").notNull(),
    target: text("target"),
    ipHash: text("ip_hash"),
    uaHash: text("ua_hash"),
    ts: timestamp("ts", { withTimezone: true }).notNull().defaultNow(),
    prevHash: text("prev_hash").notNull(),
    hash: text("hash").notNull(),
  },
  (t) => [index("audit_ws_seq").on(t.workspaceId, t.seq)],
);

// ── Settings ────────────────────────────────────────────────────────────────

export const workspaceSettings = pgTable("workspace_settings", {
  workspaceId: uuid("workspace_id").primaryKey().references(() => workspaces.id),
  settings: jsonb("settings").notNull().default(sql`'{}'::jsonb`),
});

// ── Bridge plumbing (drained by comms-web-gateway; inert until it runs) ──────

/** Web-origin sends awaiting MLS encryption + submit onto the relay. */
export const outbox = pgTable(
  "outbox",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    channelId: uuid("channel_id").notNull().references(() => channels.id),
    groupId: text("group_id"),
    authorSub: text("author_sub").notNull(),
    clientMsgId: text("client_msg_id").notNull(),
    bodyEnc: text("body_enc").notNull(),
    status: text("status").notNull().default("pending"), // pending|committed|failed
    groupSeq: bigint("group_seq", { mode: "number" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("outbox_client_msg").on(t.workspaceId, t.clientMsgId),
    index("outbox_status").on(t.status, t.createdAt),
  ],
);

/** Event-sourced shape preserved for the bridge (per-field LWW, Lamport clock). */
export const domainEvents = pgTable(
  "domain_events",
  {
    seq: bigserial("seq", { mode: "number" }).primaryKey(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    entityType: text("entity_type").notNull(),
    entityId: uuid("entity_id").notNull(),
    op: text("op").notNull(), // upsert|delete
    fields: jsonb("fields"),
    lamportCounter: bigint("lamport_counter", { mode: "number" }),
    lamportActor: text("lamport_actor"),
    groupSeq: bigint("group_seq", { mode: "number" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("domain_events_ws_entity").on(t.workspaceId, t.entityType, t.entityId)],
);

/**
 * Email suppression list (CAN-SPAM / CASL). One row per address that has
 * unsubscribed; GLOBAL (not workspace-scoped) — an unsubscribe applies to all
 * transactional invite mail from the system. Checked before every send. Honoring
 * an unsubscribe is mandatory and permanent until the person opts back in.
 */
export const emailSuppression = pgTable("email_suppression", {
  email: text("email").primaryKey(), // lowercased
  reason: text("reason"), // unsubscribe-link | one-click | admin | bounce
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Read-only mirror of the relay's BLAKE3 chain, for the web audit screen. */
export const auditMirror = pgTable(
  "audit_mirror",
  {
    sequence: bigint("sequence", { mode: "number" }).notNull(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    prevHash: text("prev_hash").notNull(),
    recordHash: text("record_hash").notNull(),
    event: jsonb("event").notNull(),
    tsMs: bigint("ts_ms", { mode: "number" }).notNull(),
  },
  (t) => [primaryKey({ columns: [t.workspaceId, t.sequence] })],
);

// ── Agentic CRM (COMMS-AGENTS) ───────────────────────────────────────────────
//
// The agent BRAIN + HARNESS layered on top of the agents-as-members scaffolding.
// Personas are layered system-prompt templates (cloneable, user-customizable) with
// a tool allow-list, a model tier, and agentile skills. Every tool call lands in
// `agent_tool_calls` (the transparency log) and the BLAKE3 `audit_log`. Content
// columns (`_enc`) are AES-256-GCM per-workspace (lib/security/crypto.ts); the
// no-pii allow-list test enforces this. pgvector powers documents RAG + the Neon
// MemoryStore fallback.

/** A persona = a layered prompt template + tool allow-list + model tier + skills.
 *  `is_template` rows are the org defaults; clones drop the flag. */
export const agentPersonas = pgTable(
  "agent_personas",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    agentId: uuid("agent_id").references(() => agents.id), // bound agent member (NULL for unbound templates)
    key: text("key").notNull(), // stable persona key, e.g. executive-assistant
    name: text("name").notNull(),
    baseTemplate: text("base_template").notNull(), // which built-in template this derives from
    modelJson: jsonb("model_json").notNull(), // { gateway: string, frontier?: string }
    toolsJson: jsonb("tools_json").notNull(), // string[] tool allow-list
    maxSteps: integer("max_steps").notNull().default(8),
    temperature: integer("temperature").notNull().default(30), // ×100 (0.30) — integer-safe
    enabled: boolean("enabled").notNull().default(true),
    isTemplate: boolean("is_template").notNull().default(false),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("agent_personas_ws_key").on(t.workspaceId, t.key),
    index("agent_personas_ws").on(t.workspaceId),
  ],
);

/** Editable persona prompt layers (1–4). Layer 6 guardrails are force-included in
 *  code and NEVER stored here — they cannot be removed. */
export const agentPrompts = pgTable(
  "agent_prompts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    personaId: uuid("persona_id").notNull().references(() => agentPersonas.id),
    layer: integer("layer").notNull(), // 1=persona 2=capabilities 3=workspace-knowledge 4=skills
    contentEnc: text("content_enc").notNull(),
    updatedBySub: text("updated_by_sub").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("agent_prompts_persona_layer").on(t.personaId, t.layer)],
);

/** Agentile skill bundles (rules + a workflow) a workspace enables per persona. */
export const agentSkills = pgTable(
  "agent_skills",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    personaId: uuid("persona_id").notNull().references(() => agentPersonas.id),
    skillKey: text("skill_key").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    configJson: jsonb("config_json"),
  },
  (t) => [uniqueIndex("agent_skills_persona_skill").on(t.personaId, t.skillKey)],
);

/** A chat thread between a human and an agent persona, scoped to a channel/deal. */
export const agentThreads = pgTable(
  "agent_threads",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    agentId: uuid("agent_id").references(() => agents.id),
    personaId: uuid("persona_id").references(() => agentPersonas.id),
    channelId: uuid("channel_id").references(() => channels.id),
    dealId: uuid("deal_id").references(() => deals.id),
    accountId: uuid("account_id").references(() => accounts.id),
    invokedBySub: text("invoked_by_sub").notNull(),
    title: text("title").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("agent_threads_ws").on(t.workspaceId, t.invokedBySub)],
);

export const agentMessages = pgTable(
  "agent_messages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    threadId: uuid("thread_id").notNull().references(() => agentThreads.id),
    role: text("role").notNull(), // user|assistant|tool
    contentEnc: text("content_enc").notNull(),
    toolTraceJson: jsonb("tool_trace_json"), // [{tool,args,done}]
    seq: integer("seq").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("agent_messages_thread_seq").on(t.threadId, t.seq)],
);

/** The transparency log: one row per tool call, written BEFORE execution (args
 *  truncated + hashed), then updated with the result hash + approval status. */
export const agentToolCalls = pgTable(
  "agent_tool_calls",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    threadId: uuid("thread_id").references(() => agentThreads.id),
    personaId: uuid("persona_id").references(() => agentPersonas.id),
    invokedBySub: text("invoked_by_sub"),
    tool: text("tool").notNull(),
    argsHash: text("args_hash").notNull(),
    argsRedacted: text("args_redacted"), // truncated, key-scrubbed args (NOT ciphertext, NOT secrets)
    approvalStatus: text("approval_status").notNull().default("auto"), // auto|pending|approved|rejected
    resultHash: text("result_hash"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("agent_tool_calls_ws").on(t.workspaceId, t.createdAt), index("agent_tool_calls_thread").on(t.threadId)],
);

/** HITL approvals queue for write/terminal tools (risk-tiered). */
export const agentApprovals = pgTable(
  "agent_approvals",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    toolCallId: uuid("tool_call_id").notNull().references(() => agentToolCalls.id),
    tool: text("tool").notNull(), // denormalized for the inbox listing
    risk: text("risk").notNull(), // low|medium|high
    payloadEnc: text("payload_enc"), // the executable action (encrypted) — applied on approval
    requestedBySub: text("requested_by_sub").notNull(),
    personaId: uuid("persona_id").references(() => agentPersonas.id),
    decidedBySub: text("decided_by_sub"),
    status: text("status").notNull().default("pending"), // pending|approved|rejected|auto
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
  },
  (t) => [index("agent_approvals_ws_status").on(t.workspaceId, t.status)],
);

// ── Documents + RAG (Notetaker) ──────────────────────────────────────────────

export const documents = pgTable(
  "documents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    dealId: uuid("deal_id").references(() => deals.id),
    accountId: uuid("account_id").references(() => accounts.id),
    channelId: uuid("channel_id").references(() => channels.id),
    blobUrl: text("blob_url").notNull(),
    name: text("name").notNull(),
    mime: text("mime"),
    textEnc: text("text_enc"), // extracted text, encrypted per-workspace
    uploadedBySub: text("uploaded_by_sub").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("documents_ws").on(t.workspaceId)],
);

export const documentChunks = pgTable(
  "document_chunks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    documentId: uuid("document_id").notNull().references(() => documents.id),
    ord: integer("ord").notNull().default(0),
    textEnc: text("text_enc").notNull(),
    embedding: vector("embedding", { dimensions: EMBEDDING_DIM }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("document_chunks_ws_doc").on(t.workspaceId, t.documentId)],
);

// ── Knowledge graph — NeonMemoryStore fallback ONLY (mem-gateway is primary) ──

export const memoryNodes = pgTable(
  "memory_nodes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    repo: text("repo").notNull(), // crm:<workspaceId>
    plane: text("plane").notNull().default("asserted"), // asserted|derived
    kind: text("kind").notNull(),
    contentEnc: text("content_enc").notNull(),
    anchorsJson: jsonb("anchors_json"), // entity refs {entity,id}[]
    trustTier: text("trust_tier").notNull().default("agent-asserted"),
    // derived-deterministic | human-confirmed | agent-asserted | inferred-advisory
    confidence: integer("confidence").notNull().default(50), // 0..100
    signature: text("signature"), // persona key signature over the content hash
    contentHash: text("content_hash").notNull(),
    embedding: vector("embedding", { dimensions: EMBEDDING_DIM }),
    validFrom: timestamp("valid_from", { withTimezone: true }).notNull().defaultNow(),
    status: text("status").notNull().default("active"), // active|retracted
    createdBySub: text("created_by_sub"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("memory_nodes_ws_repo").on(t.workspaceId, t.repo)],
);

export const memoryEdges = pgTable(
  "memory_edges",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    repo: text("repo").notNull(),
    fromNode: uuid("from_node").notNull().references(() => memoryNodes.id),
    toNode: uuid("to_node").notNull().references(() => memoryNodes.id),
    kind: text("kind").notNull(),
    evidenceEnc: text("evidence_enc"),
    status: text("status").notNull().default("quarantined"), // quarantined|confirmed
    signature: text("signature"),
    createdBySub: text("created_by_sub"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("memory_edges_ws_repo").on(t.workspaceId, t.repo)],
);

// ── comms-agent-runner job queue (privileged tools delegated to the daemon) ───

export const runnerJobs = pgTable(
  "runner_jobs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    toolCallId: uuid("tool_call_id").references(() => agentToolCalls.id),
    kind: text("kind").notNull(), // web.search|web.fetch|terminal.exec|code.run|chart.render
    payloadEnc: text("payload_enc").notNull(),
    status: text("status").notNull().default("pending"), // pending|running|done|failed
    resultEnc: text("result_enc"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("runner_jobs_ws_status").on(t.workspaceId, t.status)],
);

/** Encrypted per-workspace/per-persona keys (cgk_/frontier/search). The runner's
 *  OS keyring is the primary custody for privileged provider keys; this table holds
 *  the BFF-side encrypted tool keys (gateway cgk_) — never logged, never returned raw. */
export const agentKeys = pgTable(
  "agent_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    personaId: uuid("persona_id").references(() => agentPersonas.id),
    purpose: text("purpose").notNull(), // gateway|frontier|search
    ciphertext: text("ciphertext").notNull(), // AES-256-GCM per-workspace
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("agent_keys_ws_persona_purpose").on(t.workspaceId, t.personaId, t.purpose)],
);

// ── CRM depth (COMMS-CRM-DEPTH) ──────────────────────────────────────────────
//
// Each account/deal/contact becomes a deep, clickable FILE: a full admin-defined
// custom-field engine + a typed notes/journal timeline + an automatic, value-free
// activity feed + tags. Free-text/PII columns are `_enc` (per-workspace AES-256-GCM);
// only controlled/derived values (option keys, numbers, dates, non-PII activity
// summaries) are cleartext so they stay queryable without decrypting.
// `crm_entity` ∈ {account, deal, contact}.

/** Admin-defined custom field DEFINITIONS, per workspace + entity. Drive the dynamic
 *  forms, the L0 column chooser, AND the agents' dynamic tool input schemas. */
export const crmFieldDefs = pgTable(
  "crm_field_defs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    entity: text("entity").notNull(), // account|deal|contact
    key: text("key").notNull(), // stable machine key, e.g. industry
    label: text("label").notNull(),
    type: text("type").notNull(), // text|longtext|number|currency|date|select|multiselect|boolean|url|email|phone|user
    optionsJson: jsonb("options_json"), // [{key,label}] for select/multiselect
    required: boolean("required").notNull().default(false),
    sensitive: boolean("sensitive").notNull().default(true), // encrypt-only; false ⇒ also index value_key/value_num
    ord: integer("ord").notNull().default(0),
    enabled: boolean("enabled").notNull().default(true),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("crm_field_defs_ws_entity_key").on(t.workspaceId, t.entity, t.key)],
);

/** Custom field VALUES. `value_enc` always holds the canonical (encrypted) value;
 *  `value_key`/`value_num` hold controlled/numeric/date forms for query+sort. */
export const crmFieldValues = pgTable(
  "crm_field_values",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    entity: text("entity").notNull(),
    recordId: uuid("record_id").notNull(),
    fieldId: uuid("field_id").notNull().references(() => crmFieldDefs.id),
    valueEnc: text("value_enc"), // ciphertext (free-text/PII; canonical value)
    valueKey: text("value_key"), // option key(s) for select/multiselect (non-PII, queryable)
    valueNum: bigint("value_num", { mode: "number" }), // number/currency (×100) or date epoch-ms
    updatedBySub: text("updated_by_sub").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("crm_field_values_record_field").on(t.workspaceId, t.recordId, t.fieldId),
    index("crm_field_values_ws_entity").on(t.workspaceId, t.entity, t.recordId),
  ],
);

/** Typed journal/notes timeline per record (encrypted free-text). */
export const crmNotes = pgTable(
  "crm_notes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    entity: text("entity").notNull(),
    recordId: uuid("record_id").notNull(),
    type: text("type").notNull(), // note|journal|call|meeting|email
    titleEnc: text("title_enc"),
    bodyEnc: text("body_enc").notNull(),
    authorSub: text("author_sub").notNull(),
    byAgent: boolean("by_agent").notNull().default(false),
    personaId: uuid("persona_id").references(() => agentPersonas.id),
    pinned: boolean("pinned").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("crm_notes_ws_record").on(t.workspaceId, t.entity, t.recordId)],
);

/** Threaded comments on a note (the deepest drill level). */
export const crmNoteComments = pgTable(
  "crm_note_comments",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    noteId: uuid("note_id").notNull().references(() => crmNotes.id),
    bodyEnc: text("body_enc").notNull(),
    authorSub: text("author_sub").notNull(),
    byAgent: boolean("by_agent").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("crm_note_comments_note").on(t.noteId)],
);

/** Automatic, VALUE-FREE activity feed (built from controlled templates — never raw
 *  values). `meta_json` holds ids/hashes only. */
export const crmActivity = pgTable(
  "crm_activity",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    entity: text("entity").notNull(),
    recordId: uuid("record_id").notNull(),
    kind: text("kind").notNull(), // created|field_changed|stage_changed|note_added|document_added|contact_linked|tagged|agent_action
    actorSub: text("actor_sub"),
    byAgent: boolean("by_agent").notNull().default(false),
    summary: text("summary").notNull(), // SHORT + VALUE-FREE (e.g. "Stage Lead→Qualified")
    metaJson: jsonb("meta_json"), // ids/hashes only, never raw values
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("crm_activity_ws_record").on(t.workspaceId, t.entity, t.recordId, t.createdAt)],
);

/** Tags (categorical labels) for cross-record filtering. */
export const crmTags = pgTable(
  "crm_tags",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id").notNull().references(() => workspaces.id),
    label: text("label").notNull(),
    color: text("color"),
  },
  (t) => [uniqueIndex("crm_tags_ws_label").on(t.workspaceId, t.label)],
);

export const crmRecordTags = pgTable(
  "crm_record_tags",
  {
    workspaceId: uuid("workspace_id").notNull(),
    entity: text("entity").notNull(),
    recordId: uuid("record_id").notNull(),
    tagId: uuid("tag_id").notNull().references(() => crmTags.id),
  },
  (t) => [primaryKey({ columns: [t.entity, t.recordId, t.tagId] }), index("crm_record_tags_ws").on(t.workspaceId)],
);
