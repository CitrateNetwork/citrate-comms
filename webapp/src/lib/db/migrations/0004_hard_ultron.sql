ALTER TABLE "agent_approvals" ADD COLUMN "tool" text NOT NULL;--> statement-breakpoint
ALTER TABLE "agent_approvals" ADD COLUMN "payload_enc" text;--> statement-breakpoint
ALTER TABLE "agent_approvals" ADD COLUMN "persona_id" uuid;--> statement-breakpoint
ALTER TABLE "agent_approvals" ADD CONSTRAINT "agent_approvals_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;