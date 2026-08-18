ALTER TABLE "import_jobs" ADD COLUMN "min_confidence" real;--> statement-breakpoint
ALTER TABLE "import_rows" ADD COLUMN "confidence" real;