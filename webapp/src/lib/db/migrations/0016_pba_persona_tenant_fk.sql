-- PBA-L3c-001: bind every persona-config row to its persona's workspace.
-- 1) Remove cross-tenant rows planted before the fix (a row whose workspace_id differs from
--    its persona's workspace_id is, by construction, another tenant's write; the app never
--    reads it — every read is predicated on the row's workspace_id).
DELETE FROM "agent_prompts" p USING "agent_personas" a WHERE p."persona_id" = a."id" AND p."workspace_id" <> a."workspace_id";--> statement-breakpoint
DELETE FROM "agent_skills" s USING "agent_personas" a WHERE s."persona_id" = a."id" AND s."workspace_id" <> a."workspace_id";--> statement-breakpoint
DELETE FROM "agent_resources" r USING "agent_personas" a WHERE r."persona_id" = a."id" AND r."workspace_id" <> a."workspace_id";--> statement-breakpoint
DELETE FROM "agent_config_grants" g USING "agent_personas" a WHERE g."persona_id" = a."id" AND g."workspace_id" <> a."workspace_id";--> statement-breakpoint
-- 2) Composite key target, then the composite FKs (index first: an FK needs a unique target).
CREATE UNIQUE INDEX "agent_personas_ws_id" ON "agent_personas" USING btree ("workspace_id","id");--> statement-breakpoint
ALTER TABLE "agent_config_grants" ADD CONSTRAINT "agent_config_grants_ws_persona_fk" FOREIGN KEY ("workspace_id","persona_id") REFERENCES "public"."agent_personas"("workspace_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_prompts" ADD CONSTRAINT "agent_prompts_ws_persona_fk" FOREIGN KEY ("workspace_id","persona_id") REFERENCES "public"."agent_personas"("workspace_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_resources" ADD CONSTRAINT "agent_resources_ws_persona_fk" FOREIGN KEY ("workspace_id","persona_id") REFERENCES "public"."agent_personas"("workspace_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_skills" ADD CONSTRAINT "agent_skills_ws_persona_fk" FOREIGN KEY ("workspace_id","persona_id") REFERENCES "public"."agent_personas"("workspace_id","id") ON DELETE no action ON UPDATE no action;
