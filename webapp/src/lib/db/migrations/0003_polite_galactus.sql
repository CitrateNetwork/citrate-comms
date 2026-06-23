CREATE TABLE "crm_activity" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity" text NOT NULL,
	"record_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"actor_sub" text,
	"by_agent" boolean DEFAULT false NOT NULL,
	"summary" text NOT NULL,
	"meta_json" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crm_field_defs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity" text NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"type" text NOT NULL,
	"options_json" jsonb,
	"required" boolean DEFAULT false NOT NULL,
	"sensitive" boolean DEFAULT true NOT NULL,
	"ord" integer DEFAULT 0 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crm_field_values" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity" text NOT NULL,
	"record_id" uuid NOT NULL,
	"field_id" uuid NOT NULL,
	"value_enc" text,
	"value_key" text,
	"value_num" bigint,
	"updated_by_sub" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crm_note_comments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"note_id" uuid NOT NULL,
	"body_enc" text NOT NULL,
	"author_sub" text NOT NULL,
	"by_agent" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crm_notes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity" text NOT NULL,
	"record_id" uuid NOT NULL,
	"type" text NOT NULL,
	"title_enc" text,
	"body_enc" text NOT NULL,
	"author_sub" text NOT NULL,
	"by_agent" boolean DEFAULT false NOT NULL,
	"persona_id" uuid,
	"pinned" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crm_record_tags" (
	"workspace_id" uuid NOT NULL,
	"entity" text NOT NULL,
	"record_id" uuid NOT NULL,
	"tag_id" uuid NOT NULL,
	CONSTRAINT "crm_record_tags_entity_record_id_tag_id_pk" PRIMARY KEY("entity","record_id","tag_id")
);
--> statement-breakpoint
CREATE TABLE "crm_tags" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"label" text NOT NULL,
	"color" text
);
--> statement-breakpoint
ALTER TABLE "crm_activity" ADD CONSTRAINT "crm_activity_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_field_defs" ADD CONSTRAINT "crm_field_defs_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_field_values" ADD CONSTRAINT "crm_field_values_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_field_values" ADD CONSTRAINT "crm_field_values_field_id_crm_field_defs_id_fk" FOREIGN KEY ("field_id") REFERENCES "public"."crm_field_defs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_note_comments" ADD CONSTRAINT "crm_note_comments_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_note_comments" ADD CONSTRAINT "crm_note_comments_note_id_crm_notes_id_fk" FOREIGN KEY ("note_id") REFERENCES "public"."crm_notes"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_notes" ADD CONSTRAINT "crm_notes_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_notes" ADD CONSTRAINT "crm_notes_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_record_tags" ADD CONSTRAINT "crm_record_tags_tag_id_crm_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."crm_tags"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crm_tags" ADD CONSTRAINT "crm_tags_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "crm_activity_ws_record" ON "crm_activity" USING btree ("workspace_id","entity","record_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "crm_field_defs_ws_entity_key" ON "crm_field_defs" USING btree ("workspace_id","entity","key");--> statement-breakpoint
CREATE UNIQUE INDEX "crm_field_values_record_field" ON "crm_field_values" USING btree ("workspace_id","record_id","field_id");--> statement-breakpoint
CREATE INDEX "crm_field_values_ws_entity" ON "crm_field_values" USING btree ("workspace_id","entity","record_id");--> statement-breakpoint
CREATE INDEX "crm_note_comments_note" ON "crm_note_comments" USING btree ("note_id");--> statement-breakpoint
CREATE INDEX "crm_notes_ws_record" ON "crm_notes" USING btree ("workspace_id","entity","record_id");--> statement-breakpoint
CREATE INDEX "crm_record_tags_ws" ON "crm_record_tags" USING btree ("workspace_id");--> statement-breakpoint
CREATE UNIQUE INDEX "crm_tags_ws_label" ON "crm_tags" USING btree ("workspace_id","label");