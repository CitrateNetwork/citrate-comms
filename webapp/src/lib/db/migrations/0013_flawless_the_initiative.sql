CREATE TABLE "calendar_connections" (
	"workspace_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"provider" text NOT NULL,
	"account_email_enc" text,
	"access_token_enc" text,
	"refresh_token_enc" text,
	"token_expires_at" timestamp with time zone,
	"calendar_id" text,
	"sync_token" text,
	"channel_expires_at" timestamp with time zone,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "calendar_connections_workspace_id_sub_provider_pk" PRIMARY KEY("workspace_id","sub","provider")
);
--> statement-breakpoint
CREATE TABLE "calendar_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"kind" text DEFAULT 'meeting' NOT NULL,
	"title_enc" text NOT NULL,
	"description_enc" text,
	"location_enc" text,
	"starts_at" timestamp with time zone NOT NULL,
	"ends_at" timestamp with time zone NOT NULL,
	"all_day" boolean DEFAULT false NOT NULL,
	"timezone" text DEFAULT 'UTC' NOT NULL,
	"status" text DEFAULT 'confirmed' NOT NULL,
	"channel_id" uuid,
	"project_id" uuid,
	"task_id" uuid,
	"deal_id" uuid,
	"recurrence" text,
	"external_provider" text,
	"external_calendar_id" text,
	"external_id" text,
	"external_etag" text,
	"external_updated_at" timestamp with time zone,
	"created_by_sub" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "event_attendees" (
	"workspace_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"raci_role" text,
	"response" text DEFAULT 'needsAction' NOT NULL,
	"notified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "event_attendees_event_id_sub_pk" PRIMARY KEY("event_id","sub")
);
--> statement-breakpoint
CREATE TABLE "event_reminders" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"remind_at" timestamp with time zone NOT NULL,
	"channel" text DEFAULT 'both' NOT NULL,
	"sent_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "members" ADD COLUMN "timezone" text;--> statement-breakpoint
ALTER TABLE "calendar_events" ADD CONSTRAINT "calendar_events_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "event_attendees" ADD CONSTRAINT "event_attendees_event_id_calendar_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."calendar_events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "event_reminders" ADD CONSTRAINT "event_reminders_event_id_calendar_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."calendar_events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "calendar_events_ws_start" ON "calendar_events" USING btree ("workspace_id","starts_at");--> statement-breakpoint
CREATE INDEX "calendar_events_ws_task" ON "calendar_events" USING btree ("workspace_id","task_id");--> statement-breakpoint
CREATE UNIQUE INDEX "calendar_events_external" ON "calendar_events" USING btree ("external_provider","external_id");--> statement-breakpoint
CREATE INDEX "event_attendees_ws_sub" ON "event_attendees" USING btree ("workspace_id","sub");--> statement-breakpoint
CREATE INDEX "event_reminders_due" ON "event_reminders" USING btree ("remind_at","sent_at");--> statement-breakpoint
CREATE INDEX "event_reminders_event" ON "event_reminders" USING btree ("event_id");