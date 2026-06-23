CREATE TABLE "accounts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"name" text NOT NULL,
	"domain" text,
	"owner_sub" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"member_sub" text NOT NULL,
	"name" text NOT NULL,
	"purpose" text,
	"kind" text,
	"status" text DEFAULT 'active' NOT NULL,
	"sponsor_sub" text,
	"config" jsonb,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"seq" bigserial PRIMARY KEY NOT NULL,
	"workspace_id" uuid NOT NULL,
	"actor_sub" text,
	"event" text NOT NULL,
	"target" text,
	"ip_hash" text,
	"ua_hash" text,
	"ts" timestamp with time zone DEFAULT now() NOT NULL,
	"prev_hash" text NOT NULL,
	"hash" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_mirror" (
	"sequence" bigint NOT NULL,
	"workspace_id" uuid NOT NULL,
	"prev_hash" text NOT NULL,
	"record_hash" text NOT NULL,
	"event" jsonb NOT NULL,
	"ts_ms" bigint NOT NULL,
	CONSTRAINT "audit_mirror_workspace_id_sequence_pk" PRIMARY KEY("workspace_id","sequence")
);
--> statement-breakpoint
CREATE TABLE "board_columns" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"board_id" uuid NOT NULL,
	"name" text NOT NULL,
	"ord" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "boards" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"project_id" uuid,
	"name" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "channel_members" (
	"workspace_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"added_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_members_channel_id_sub_pk" PRIMARY KEY("channel_id","sub")
);
--> statement-breakpoint
CREATE TABLE "channels" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"topic" text,
	"is_starred" boolean DEFAULT false NOT NULL,
	"has_agent" boolean DEFAULT false NOT NULL,
	"group_id" text,
	"bridged" boolean DEFAULT false NOT NULL,
	"created_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "contacts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"account_id" uuid,
	"name" text NOT NULL,
	"email_enc" text,
	"title" text,
	"owner_sub" text,
	"last_touch" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "deals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"account_id" uuid,
	"name" text NOT NULL,
	"value_minor" bigint DEFAULT 0 NOT NULL,
	"stage" text DEFAULT 'Lead' NOT NULL,
	"priority" text,
	"owner_sub" text,
	"close_date" timestamp with time zone,
	"linked_channel_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "devices" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"label" text,
	"signing_method" text,
	"last_seen" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "domain_events" (
	"seq" bigserial PRIMARY KEY NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" uuid NOT NULL,
	"op" text NOT NULL,
	"fields" jsonb,
	"lamport_counter" bigint,
	"lamport_actor" text,
	"group_seq" bigint,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "invites" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"workspace_id" uuid NOT NULL,
	"email" text NOT NULL,
	"role" text NOT NULL,
	"scope_channel_id" uuid,
	"invited_by_sub" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"accepted_by_sub" text,
	"accepted_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ledger_entries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"source_message_id" uuid,
	"kind" text NOT NULL,
	"text_enc" text NOT NULL,
	"by_sub" text NOT NULL,
	"owner_sub" text,
	"due" timestamp with time zone,
	"status" text DEFAULT 'open' NOT NULL,
	"proposed_by_agent" boolean DEFAULT false NOT NULL,
	"record_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "members" (
	"workspace_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"wallet_address" text,
	"display_name" text,
	"email" text,
	"role" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"kyc_status" text,
	"is_agent" boolean DEFAULT false NOT NULL,
	"devices_count" integer DEFAULT 0 NOT NULL,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "members_workspace_id_sub_pk" PRIMARY KEY("workspace_id","sub")
);
--> statement-breakpoint
CREATE TABLE "message_links" (
	"message_id" uuid NOT NULL,
	"workspace_id" uuid NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" uuid NOT NULL,
	CONSTRAINT "message_links_message_id_entity_type_entity_id_pk" PRIMARY KEY("message_id","entity_type","entity_id")
);
--> statement-breakpoint
CREATE TABLE "messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"thread_id" uuid,
	"parent_id" uuid,
	"author_sub" text NOT NULL,
	"from_agent" boolean DEFAULT false NOT NULL,
	"body_enc" text NOT NULL,
	"state" text DEFAULT 'sent' NOT NULL,
	"seq" bigint NOT NULL,
	"group_seq" bigint,
	"epoch" bigint,
	"sender_wallet" text,
	"ciphertext_hash" text,
	"client_msg_id" text,
	"on_behalf_of" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "outbox" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"group_id" text,
	"author_sub" text NOT NULL,
	"client_msg_id" text NOT NULL,
	"body_enc" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"group_seq" bigint,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "projects" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"name" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "role_assertions" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"workspace_id" uuid NOT NULL,
	"subject_sub" text NOT NULL,
	"role" text NOT NULL,
	"scope_channel_id" uuid,
	"issuer_sub" text NOT NULL,
	"not_after" timestamp with time zone,
	"signature" text,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tasks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"project_id" uuid,
	"board_id" uuid,
	"column_id" uuid,
	"title" text NOT NULL,
	"description" text,
	"assignee_sub" text,
	"status" text DEFAULT 'Backlog' NOT NULL,
	"priority" text,
	"due" timestamp with time zone,
	"ord" integer DEFAULT 0 NOT NULL,
	"linked_channel_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threads" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"title" text NOT NULL,
	"author_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "workspace_settings" (
	"workspace_id" uuid PRIMARY KEY NOT NULL,
	"settings" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "workspaces" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"owner_sub" text NOT NULL,
	"enc_key_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "workspaces_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
ALTER TABLE "accounts" ADD CONSTRAINT "accounts_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_mirror" ADD CONSTRAINT "audit_mirror_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "board_columns" ADD CONSTRAINT "board_columns_board_id_boards_id_fk" FOREIGN KEY ("board_id") REFERENCES "public"."boards"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "boards" ADD CONSTRAINT "boards_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "boards" ADD CONSTRAINT "boards_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_members" ADD CONSTRAINT "channel_members_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channels" ADD CONSTRAINT "channels_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "contacts" ADD CONSTRAINT "contacts_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "contacts" ADD CONSTRAINT "contacts_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deals" ADD CONSTRAINT "deals_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deals" ADD CONSTRAINT "deals_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deals" ADD CONSTRAINT "deals_linked_channel_id_channels_id_fk" FOREIGN KEY ("linked_channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "domain_events" ADD CONSTRAINT "domain_events_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invites" ADD CONSTRAINT "invites_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ledger_entries" ADD CONSTRAINT "ledger_entries_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ledger_entries" ADD CONSTRAINT "ledger_entries_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ledger_entries" ADD CONSTRAINT "ledger_entries_source_message_id_messages_id_fk" FOREIGN KEY ("source_message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "members" ADD CONSTRAINT "members_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "message_links" ADD CONSTRAINT "message_links_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "outbox" ADD CONSTRAINT "outbox_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "outbox" ADD CONSTRAINT "outbox_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_assertions" ADD CONSTRAINT "role_assertions_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_linked_channel_id_channels_id_fk" FOREIGN KEY ("linked_channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threads" ADD CONSTRAINT "threads_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threads" ADD CONSTRAINT "threads_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_settings" ADD CONSTRAINT "workspace_settings_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "accounts_ws" ON "accounts" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "agents_ws" ON "agents" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "audit_ws_seq" ON "audit_log" USING btree ("workspace_id","seq");--> statement-breakpoint
CREATE INDEX "board_columns_ws_board" ON "board_columns" USING btree ("workspace_id","board_id");--> statement-breakpoint
CREATE INDEX "boards_ws_project" ON "boards" USING btree ("workspace_id","project_id");--> statement-breakpoint
CREATE INDEX "channel_members_ws" ON "channel_members" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "channels_ws_kind" ON "channels" USING btree ("workspace_id","kind");--> statement-breakpoint
CREATE INDEX "contacts_ws_account" ON "contacts" USING btree ("workspace_id","account_id");--> statement-breakpoint
CREATE INDEX "deals_ws_stage" ON "deals" USING btree ("workspace_id","stage");--> statement-breakpoint
CREATE INDEX "deals_ws_account" ON "deals" USING btree ("workspace_id","account_id");--> statement-breakpoint
CREATE INDEX "devices_ws_sub" ON "devices" USING btree ("workspace_id","sub");--> statement-breakpoint
CREATE INDEX "domain_events_ws_entity" ON "domain_events" USING btree ("workspace_id","entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "invites_ws" ON "invites" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "ledger_ws_channel" ON "ledger_entries" USING btree ("workspace_id","channel_id");--> statement-breakpoint
CREATE INDEX "members_ws_role" ON "members" USING btree ("workspace_id","role");--> statement-breakpoint
CREATE INDEX "messages_channel_seq" ON "messages" USING btree ("workspace_id","channel_id","seq");--> statement-breakpoint
CREATE INDEX "messages_thread" ON "messages" USING btree ("workspace_id","thread_id");--> statement-breakpoint
CREATE UNIQUE INDEX "outbox_client_msg" ON "outbox" USING btree ("workspace_id","client_msg_id");--> statement-breakpoint
CREATE INDEX "outbox_status" ON "outbox" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "projects_ws" ON "projects" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "role_assertions_ws_subject" ON "role_assertions" USING btree ("workspace_id","subject_sub");--> statement-breakpoint
CREATE INDEX "tasks_ws_status" ON "tasks" USING btree ("workspace_id","status");--> statement-breakpoint
CREATE INDEX "tasks_ws_column" ON "tasks" USING btree ("workspace_id","column_id");--> statement-breakpoint
CREATE INDEX "threads_ws_channel" ON "threads" USING btree ("workspace_id","channel_id");