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
  body: z.string().trim().min(1).max(8000),
  threadId: z.string().uuid().optional(),
  parentId: z.string().uuid().optional(),
  clientMsgId: z.string().max(64).optional(),
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

// --- Agents ---
export const addAgentSchema = z.object({
  name: z.string().trim().min(1).max(80),
  purpose: z.string().trim().max(280).optional(),
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
