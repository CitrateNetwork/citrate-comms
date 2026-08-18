/**
 * Zod request schemas — validated at every BFF boundary (reject unknown keys).
 */
import { z } from "zod";

export const createWorkspaceSchema = z.object({
  name: z.string().trim().min(2).max(60),
});

export const createChannelSchema = z.object({
  workspaceId: z.string().uuid(),
  kind: z.enum(["channel", "forum", "dm"]),
  name: z.string().trim().min(1).max(60),
  topic: z.string().trim().max(280).optional(),
  memberSubs: z.array(z.string()).max(200).optional(),
});

export const sendMessageSchema = z.object({
  body: z.string().trim().max(8000), // may be empty when attachments are present (checked in the route)
  threadId: z.string().uuid().optional(),
  parentId: z.string().uuid().optional(),
  clientMsgId: z.string().max(64).optional(),
  attachmentIds: z.array(z.string().uuid()).max(10).optional(),
});

export const witnessSchema = z.object({
  sourceMessageId: z.string().uuid().optional(),
  kind: z.enum(["decision", "commitment", "resolved"]),
  text: z.string().trim().min(1).max(2000),
  ownerSub: z.string().optional(),
  due: z.string().datetime().optional(),
});

export const inviteSchema = z.object({
  workspaceId: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(["Admin", "Member", "Partner", "Guest"]),
  scopeChannelId: z.string().uuid().optional(),
});

/** Batch invite — many emails, one role/scope, sent in one action. */
export const batchInviteSchema = z.object({
  workspaceId: z.string().uuid(),
  emails: z.array(z.string().email()).min(1).max(100),
  role: z.enum(["Admin", "Member", "Partner", "Guest"]),
  scopeChannelId: z.string().uuid().optional(),
});

// --- CRM ---
export const createAccountSchema = z.object({
  name: z.string().trim().min(1).max(120),
  domain: z.string().trim().max(120).optional(),
});
export const createDealSchema = z.object({
  accountId: z.string().uuid(),
  name: z.string().trim().min(1).max(120),
  valueMinor: z.number().int().min(0).max(1_000_000_000_000).default(0),
});
export const moveDealSchema = z.object({
  dealId: z.string().uuid(),
  stage: z.enum(["Lead", "Qualified", "Proposal", "Won", "Lost"]),
});
export const createContactSchema = z.object({
  name: z.string().trim().min(1).max(120),
  title: z.string().trim().max(120).optional(),
  accountId: z.string().uuid().optional(),
});

// --- PM ---
export const createProjectSchema = z.object({
  name: z.string().trim().min(1).max(120),
});
export const createTaskSchema = z.object({
  title: z.string().trim().min(1).max(200),
  projectId: z.string().uuid().optional(),
  priority: z.enum(["low", "medium", "high"]).optional(),
});
export const moveTaskSchema = z.object({
  taskId: z.string().uuid(),
  status: z.enum(["Backlog", "Todo", "InProgress", "InReview", "Done"]),
});
export const editTaskSchema = z.object({
  title: z.string().trim().min(1).max(200).optional(),
  priority: z.enum(["low", "medium", "high"]).nullable().optional(),
  // A member's sub (assign), empty string / null (unassign).
  assigneeSub: z.string().max(200).nullable().optional(),
});

// --- Agents ---
export const addAgentSchema = z.object({
  name: z.string().trim().min(1).max(80),
  purpose: z.string().trim().max(280).optional(),
});

// --- CRM depth (D2) ---
const fieldOption = z.object({ key: z.string().min(1).max(60), label: z.string().min(1).max(80) });
export const crmFieldDefCreateSchema = z.object({
  entity: z.enum(["account", "deal", "contact"]),
  key: z.string().trim().min(1).max(60).regex(/^[a-z0-9_]+$/, "lowercase letters, numbers, underscores"),
  label: z.string().trim().min(1).max(80),
  type: z.enum(["text", "longtext", "number", "currency", "date", "select", "multiselect", "boolean", "url", "email", "phone", "user"]),
  options: z.array(fieldOption).max(50).optional(),
  required: z.boolean().optional(),
  sensitive: z.boolean().optional(),
  ord: z.number().int().min(0).max(1000).optional(),
});
export const crmFieldDefUpdateSchema = z.object({
  label: z.string().trim().min(1).max(80).optional(),
  options: z.array(fieldOption).max(50).optional(),
  required: z.boolean().optional(),
  sensitive: z.boolean().optional(),
  ord: z.number().int().min(0).max(1000).optional(),
  enabled: z.boolean().optional(),
});
export const crmFieldValueSchema = z.object({
  fieldId: z.string().uuid(),
  value: z.string().max(20000),
});
export const crmNoteSchema = z.object({
  type: z.enum(["note", "journal", "call", "meeting", "email"]),
  title: z.string().trim().max(200).optional(),
  body: z.string().trim().min(1).max(20000),
});
export const crmNotePinSchema = z.object({ noteId: z.string().uuid(), pinned: z.boolean() });
export const crmTagAddSchema = z.object({
  tagId: z.string().uuid().optional(),
  label: z.string().trim().min(1).max(40).optional(),
});
export const crmTagRemoveSchema = z.object({ tagId: z.string().uuid() });
export const crmRecordUpdateSchema = z.object({
  name: z.string().trim().min(1).max(160).optional(),
  domain: z.string().trim().max(160).optional(),
  title: z.string().trim().max(160).optional(),
  valueMinor: z.number().int().min(0).max(1_000_000_000_000).optional(),
});

// --- Approvals (D3 HITL) ---
export const approvalDecisionSchema = z.object({
  approvalId: z.string().uuid(),
  decision: z.enum(["approved", "rejected"]),
});

// --- Attachments (ATT) ---
export const documentFinalizeSchema = z.object({
  blobUrl: z.string().url().max(1000),
  name: z.string().trim().min(1).max(200),
  mime: z.string().max(120).optional(),
  accountId: z.string().uuid().optional(),
  dealId: z.string().uuid().optional(),
  channelId: z.string().uuid().optional(),
});

// --- Persona customization (S5) ---
const personaModelSchema = z.object({
  gateway: z.string().max(120),
  frontier: z.string().max(120).optional(),
  preferFrontier: z.boolean().optional(),
});
export const personaUpdateSchema = z.object({
  name: z.string().trim().min(1).max(80).optional(),
  model: personaModelSchema.optional(),
  tools: z.array(z.string().max(40)).max(40).optional(),
  maxSteps: z.number().int().min(1).max(20).optional(),
  temperature: z.number().min(0).max(1).optional(),
  enabled: z.boolean().optional(),
});
export const personaPromptSchema = z.object({
  layer: z.number().int().min(1).max(4),
  content: z.string().max(20000),
});
export const personaSkillSchema = z.object({
  skillKey: z.string().max(60),
  enabled: z.boolean(),
});
export const personaCloneSchema = z.object({ name: z.string().trim().min(1).max(80) });
export const personaImportSchema = z.object({
  name: z.string().trim().min(1).max(80),
  baseTemplate: z.string().max(60).optional(),
  model: personaModelSchema.optional(),
  tools: z.array(z.string().max(40)).max(40).optional(),
  maxSteps: z.number().int().min(1).max(20).optional(),
  temperature: z.number().min(0).max(1).optional(),
  layers: z.array(z.object({ layer: z.number().int().min(1).max(4), content: z.string().max(20000) })).max(4).optional(),
  skills: z.array(z.object({ key: z.string().max(60), enabled: z.boolean() })).max(40).optional(),
});

// --- CRM views + bulk actions (D4) ---
export const crmViewSaveSchema = z.object({
  entity: z.enum(["account", "deal", "contact"]),
  name: z.string().trim().min(1).max(80),
  shared: z.boolean().optional(),
  config: z.object({
    columns: z.array(z.string().max(60)).max(60),
    sort: z.object({ key: z.string().max(60), dir: z.enum(["asc", "desc"]) }).optional(),
    search: z.string().max(200).optional(),
  }),
});
export const crmViewDeleteSchema = z.object({ viewId: z.string().uuid() });
export const crmBulkTagSchema = z.object({
  recordIds: z.array(z.string().uuid()).min(1).max(500),
  tagId: z.string().uuid().optional(),
  label: z.string().trim().min(1).max(40).optional(),
});

// --- Settings ---
export const updateSettingsSchema = z.object({
  notifications: z.record(z.string(), z.enum(["all", "mentions", "mute"])).optional(),
  automation: z.object({ autoWitness: z.boolean() }).optional(),
  appearance: z
    .object({
      density: z.enum(["cinematic", "compact"]).optional(),
      accent: z.string().max(20).optional(),
      reducedMotion: z.boolean().optional(),
    })
    .optional(),
});
export const updateProfileSchema = z.object({
  displayName: z.string().trim().min(1).max(60),
});
