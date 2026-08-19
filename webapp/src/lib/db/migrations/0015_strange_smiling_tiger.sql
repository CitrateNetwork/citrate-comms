ALTER TABLE "messages" ADD COLUMN "pinned" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "pinned_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "messages_pinned" ON "messages" USING btree ("workspace_id","channel_id","pinned");