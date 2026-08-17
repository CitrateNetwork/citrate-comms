CREATE TABLE "import_batches" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"document_id" uuid,
	"filename" text NOT NULL,
	"mime" text,
	"status" text DEFAULT 'parsing' NOT NULL,
	"sheet_count" integer DEFAULT 0 NOT NULL,
	"error_text" text,
	"created_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "import_columns" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"sheet_id" uuid NOT NULL,
	"ord" integer DEFAULT 0 NOT NULL,
	"name" text NOT NULL,
	"type" text DEFAULT 'text' NOT NULL,
	"sensitive" boolean DEFAULT false NOT NULL,
	"null_frac" integer DEFAULT 0 NOT NULL,
	"sample_json" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "import_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"sheet_id" uuid NOT NULL,
	"mapping_id" uuid,
	"filter_json" jsonb,
	"status" text DEFAULT 'queued' NOT NULL,
	"cursor" integer DEFAULT 0 NOT NULL,
	"total" integer DEFAULT 0 NOT NULL,
	"created_count" integer DEFAULT 0 NOT NULL,
	"updated_count" integer DEFAULT 0 NOT NULL,
	"held_count" integer DEFAULT 0 NOT NULL,
	"failed_count" integer DEFAULT 0 NOT NULL,
	"error_text" text,
	"created_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "import_mappings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"sheet_id" uuid NOT NULL,
	"spec" jsonb NOT NULL,
	"approved" boolean DEFAULT false NOT NULL,
	"created_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "import_rows" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"sheet_id" uuid NOT NULL,
	"row_index" integer NOT NULL,
	"cells" jsonb NOT NULL,
	"cells_enc" text,
	"dedupe_key" text,
	"status" text DEFAULT 'new' NOT NULL,
	"linked_account_id" uuid,
	"linked_contact_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "import_sheets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"batch_id" uuid NOT NULL,
	"name" text NOT NULL,
	"ord" integer DEFAULT 0 NOT NULL,
	"header_row" integer DEFAULT 0 NOT NULL,
	"row_count" integer DEFAULT 0 NOT NULL,
	"col_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "contacts" ADD COLUMN "email_key" text;--> statement-breakpoint
ALTER TABLE "import_batches" ADD CONSTRAINT "import_batches_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_batches" ADD CONSTRAINT "import_batches_document_id_documents_id_fk" FOREIGN KEY ("document_id") REFERENCES "public"."documents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_columns" ADD CONSTRAINT "import_columns_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_columns" ADD CONSTRAINT "import_columns_sheet_id_import_sheets_id_fk" FOREIGN KEY ("sheet_id") REFERENCES "public"."import_sheets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_jobs" ADD CONSTRAINT "import_jobs_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_jobs" ADD CONSTRAINT "import_jobs_sheet_id_import_sheets_id_fk" FOREIGN KEY ("sheet_id") REFERENCES "public"."import_sheets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_jobs" ADD CONSTRAINT "import_jobs_mapping_id_import_mappings_id_fk" FOREIGN KEY ("mapping_id") REFERENCES "public"."import_mappings"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_mappings" ADD CONSTRAINT "import_mappings_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_mappings" ADD CONSTRAINT "import_mappings_sheet_id_import_sheets_id_fk" FOREIGN KEY ("sheet_id") REFERENCES "public"."import_sheets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_rows" ADD CONSTRAINT "import_rows_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_rows" ADD CONSTRAINT "import_rows_sheet_id_import_sheets_id_fk" FOREIGN KEY ("sheet_id") REFERENCES "public"."import_sheets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_sheets" ADD CONSTRAINT "import_sheets_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_sheets" ADD CONSTRAINT "import_sheets_batch_id_import_batches_id_fk" FOREIGN KEY ("batch_id") REFERENCES "public"."import_batches"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "import_batches_ws" ON "import_batches" USING btree ("workspace_id","created_at");--> statement-breakpoint
CREATE INDEX "import_columns_ws_sheet" ON "import_columns" USING btree ("workspace_id","sheet_id");--> statement-breakpoint
CREATE INDEX "import_jobs_ws_status" ON "import_jobs" USING btree ("workspace_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "import_mappings_ws_sheet" ON "import_mappings" USING btree ("workspace_id","sheet_id");--> statement-breakpoint
CREATE INDEX "import_rows_ws_sheet_idx" ON "import_rows" USING btree ("workspace_id","sheet_id","row_index");--> statement-breakpoint
CREATE INDEX "import_rows_ws_sheet_status" ON "import_rows" USING btree ("workspace_id","sheet_id","status");--> statement-breakpoint
CREATE INDEX "import_sheets_ws_batch" ON "import_sheets" USING btree ("workspace_id","batch_id");--> statement-breakpoint
CREATE INDEX "contacts_ws_email_key" ON "contacts" USING btree ("workspace_id","email_key");