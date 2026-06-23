CREATE TABLE "crm_views" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity" text NOT NULL,
	"name" text NOT NULL,
	"owner_sub" text NOT NULL,
	"config_json" jsonb NOT NULL,
	"shared" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "crm_views" ADD CONSTRAINT "crm_views_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "crm_views_ws_entity" ON "crm_views" USING btree ("workspace_id","entity");