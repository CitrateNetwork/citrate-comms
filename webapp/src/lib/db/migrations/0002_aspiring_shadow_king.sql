CREATE EXTENSION IF NOT EXISTS vector;--> statement-breakpoint
CREATE TABLE "agent_approvals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"tool_call_id" uuid NOT NULL,
	"risk" text NOT NULL,
	"requested_by_sub" text NOT NULL,
	"decided_by_sub" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"decided_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "agent_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"persona_id" uuid,
	"purpose" text NOT NULL,
	"ciphertext" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"thread_id" uuid NOT NULL,
	"role" text NOT NULL,
	"content_enc" text NOT NULL,
	"tool_trace_json" jsonb,
	"seq" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_personas" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"agent_id" uuid,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"base_template" text NOT NULL,
	"model_json" jsonb NOT NULL,
	"tools_json" jsonb NOT NULL,
	"max_steps" integer DEFAULT 8 NOT NULL,
	"temperature" integer DEFAULT 30 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"is_template" boolean DEFAULT false NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_prompts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"persona_id" uuid NOT NULL,
	"layer" integer NOT NULL,
	"content_enc" text NOT NULL,
	"updated_by_sub" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_skills" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"persona_id" uuid NOT NULL,
	"skill_key" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"config_json" jsonb
);
--> statement-breakpoint
CREATE TABLE "agent_threads" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"agent_id" uuid,
	"persona_id" uuid,
	"channel_id" uuid,
	"deal_id" uuid,
	"account_id" uuid,
	"invoked_by_sub" text NOT NULL,
	"title" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_tool_calls" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"thread_id" uuid,
	"persona_id" uuid,
	"invoked_by_sub" text,
	"tool" text NOT NULL,
	"args_hash" text NOT NULL,
	"args_redacted" text,
	"approval_status" text DEFAULT 'auto' NOT NULL,
	"result_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "document_chunks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"document_id" uuid NOT NULL,
	"ord" integer DEFAULT 0 NOT NULL,
	"text_enc" text NOT NULL,
	"embedding" vector(1024),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "documents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"deal_id" uuid,
	"account_id" uuid,
	"channel_id" uuid,
	"blob_url" text NOT NULL,
	"name" text NOT NULL,
	"mime" text,
	"text_enc" text,
	"uploaded_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "memory_edges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"repo" text NOT NULL,
	"from_node" uuid NOT NULL,
	"to_node" uuid NOT NULL,
	"kind" text NOT NULL,
	"evidence_enc" text,
	"status" text DEFAULT 'quarantined' NOT NULL,
	"signature" text,
	"created_by_sub" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "memory_nodes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"repo" text NOT NULL,
	"plane" text DEFAULT 'asserted' NOT NULL,
	"kind" text NOT NULL,
	"content_enc" text NOT NULL,
	"anchors_json" jsonb,
	"trust_tier" text DEFAULT 'agent-asserted' NOT NULL,
	"confidence" integer DEFAULT 50 NOT NULL,
	"signature" text,
	"content_hash" text NOT NULL,
	"embedding" vector(1024),
	"valid_from" timestamp with time zone DEFAULT now() NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_by_sub" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "runner_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"tool_call_id" uuid,
	"kind" text NOT NULL,
	"payload_enc" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"result_enc" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agent_approvals" ADD CONSTRAINT "agent_approvals_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_approvals" ADD CONSTRAINT "agent_approvals_tool_call_id_agent_tool_calls_id_fk" FOREIGN KEY ("tool_call_id") REFERENCES "public"."agent_tool_calls"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_keys" ADD CONSTRAINT "agent_keys_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_keys" ADD CONSTRAINT "agent_keys_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_messages" ADD CONSTRAINT "agent_messages_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_messages" ADD CONSTRAINT "agent_messages_thread_id_agent_threads_id_fk" FOREIGN KEY ("thread_id") REFERENCES "public"."agent_threads"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_personas" ADD CONSTRAINT "agent_personas_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_personas" ADD CONSTRAINT "agent_personas_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_prompts" ADD CONSTRAINT "agent_prompts_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_prompts" ADD CONSTRAINT "agent_prompts_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_skills" ADD CONSTRAINT "agent_skills_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_skills" ADD CONSTRAINT "agent_skills_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_threads" ADD CONSTRAINT "agent_threads_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_threads" ADD CONSTRAINT "agent_threads_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_threads" ADD CONSTRAINT "agent_threads_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_threads" ADD CONSTRAINT "agent_threads_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_threads" ADD CONSTRAINT "agent_threads_deal_id_deals_id_fk" FOREIGN KEY ("deal_id") REFERENCES "public"."deals"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_threads" ADD CONSTRAINT "agent_threads_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_tool_calls" ADD CONSTRAINT "agent_tool_calls_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_tool_calls" ADD CONSTRAINT "agent_tool_calls_thread_id_agent_threads_id_fk" FOREIGN KEY ("thread_id") REFERENCES "public"."agent_threads"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_tool_calls" ADD CONSTRAINT "agent_tool_calls_persona_id_agent_personas_id_fk" FOREIGN KEY ("persona_id") REFERENCES "public"."agent_personas"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "document_chunks" ADD CONSTRAINT "document_chunks_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "document_chunks" ADD CONSTRAINT "document_chunks_document_id_documents_id_fk" FOREIGN KEY ("document_id") REFERENCES "public"."documents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "documents" ADD CONSTRAINT "documents_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "documents" ADD CONSTRAINT "documents_deal_id_deals_id_fk" FOREIGN KEY ("deal_id") REFERENCES "public"."deals"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "documents" ADD CONSTRAINT "documents_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "documents" ADD CONSTRAINT "documents_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memory_edges" ADD CONSTRAINT "memory_edges_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memory_edges" ADD CONSTRAINT "memory_edges_from_node_memory_nodes_id_fk" FOREIGN KEY ("from_node") REFERENCES "public"."memory_nodes"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memory_edges" ADD CONSTRAINT "memory_edges_to_node_memory_nodes_id_fk" FOREIGN KEY ("to_node") REFERENCES "public"."memory_nodes"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memory_nodes" ADD CONSTRAINT "memory_nodes_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runner_jobs" ADD CONSTRAINT "runner_jobs_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runner_jobs" ADD CONSTRAINT "runner_jobs_tool_call_id_agent_tool_calls_id_fk" FOREIGN KEY ("tool_call_id") REFERENCES "public"."agent_tool_calls"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agent_approvals_ws_status" ON "agent_approvals" USING btree ("workspace_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "agent_keys_ws_persona_purpose" ON "agent_keys" USING btree ("workspace_id","persona_id","purpose");--> statement-breakpoint
CREATE INDEX "agent_messages_thread_seq" ON "agent_messages" USING btree ("thread_id","seq");--> statement-breakpoint
CREATE UNIQUE INDEX "agent_personas_ws_key" ON "agent_personas" USING btree ("workspace_id","key");--> statement-breakpoint
CREATE INDEX "agent_personas_ws" ON "agent_personas" USING btree ("workspace_id");--> statement-breakpoint
CREATE UNIQUE INDEX "agent_prompts_persona_layer" ON "agent_prompts" USING btree ("persona_id","layer");--> statement-breakpoint
CREATE UNIQUE INDEX "agent_skills_persona_skill" ON "agent_skills" USING btree ("persona_id","skill_key");--> statement-breakpoint
CREATE INDEX "agent_threads_ws" ON "agent_threads" USING btree ("workspace_id","invoked_by_sub");--> statement-breakpoint
CREATE INDEX "agent_tool_calls_ws" ON "agent_tool_calls" USING btree ("workspace_id","created_at");--> statement-breakpoint
CREATE INDEX "agent_tool_calls_thread" ON "agent_tool_calls" USING btree ("thread_id");--> statement-breakpoint
CREATE INDEX "document_chunks_ws_doc" ON "document_chunks" USING btree ("workspace_id","document_id");--> statement-breakpoint
CREATE INDEX "documents_ws" ON "documents" USING btree ("workspace_id");--> statement-breakpoint
CREATE INDEX "memory_edges_ws_repo" ON "memory_edges" USING btree ("workspace_id","repo");--> statement-breakpoint
CREATE INDEX "memory_nodes_ws_repo" ON "memory_nodes" USING btree ("workspace_id","repo");--> statement-breakpoint
CREATE INDEX "runner_jobs_ws_status" ON "runner_jobs" USING btree ("workspace_id","status");