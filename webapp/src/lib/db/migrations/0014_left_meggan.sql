CREATE TABLE "task_raci" (
	"workspace_id" uuid NOT NULL,
	"task_id" uuid NOT NULL,
	"sub" text NOT NULL,
	"role" text NOT NULL,
	CONSTRAINT "task_raci_task_id_sub_pk" PRIMARY KEY("task_id","sub")
);
--> statement-breakpoint
ALTER TABLE "task_raci" ADD CONSTRAINT "task_raci_task_id_tasks_id_fk" FOREIGN KEY ("task_id") REFERENCES "public"."tasks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "task_raci_ws" ON "task_raci" USING btree ("workspace_id");