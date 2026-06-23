/**
 * Pure shared enums/constants — safe to import from BOTH client and server code
 * (no DB or node imports here). The repos (crm.ts, pm.ts) re-export these so server
 * code has one import, while client components import from here to avoid pulling the
 * server-only DB client into the browser bundle.
 */
export const DEAL_STAGES = ["Lead", "Qualified", "Proposal", "Won", "Lost"] as const;
export type DealStage = (typeof DEAL_STAGES)[number];

export const TASK_STATUSES = ["Backlog", "Todo", "InProgress", "InReview", "Done"] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];
