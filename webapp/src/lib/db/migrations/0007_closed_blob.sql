CREATE TABLE "agent_config_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"grantee_sub" text NOT NULL,
	"persona_id" uuid,
	"granted_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_resources" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"persona_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"title" text NOT NULL,
	"content_enc" text,
	"url" text,
	"document_id" uuid,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agent_config_grants" ADD CONSTRAINT "agent_config_grants_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_config_grants" ADD CONSTRAINT "agent_config_grants_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_resources" ADD CONSTRAINT "agent_resources_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_resources" ADD CONSTRAINT "agent_resources_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_resources" ADD CONSTRAINT "agent_resources_document_id_documents_id_fk" FOREIGN KEY ("document_id") REFERENCES "public"."documents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agent_config_grants_ws" ON "agent_config_grants" USING btree ("workspace_id","grantee_sub");--> statement-breakpoint
CREATE INDEX "agent_resources_persona" ON "agent_resources" USING btree ("workspace_id","persona_id");