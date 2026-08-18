# Deploying citrate-comms-web (Vercel)

Project: `citrate-comms-web` · Production alias: **communications.citrate.ai**

## CLI deploy

The Vercel **Root Directory** is `webapp`, so run the CLI from the **repo root**
(`citrate-comms/`), not from `webapp/`. Running inside `webapp/` makes Vercel look
for `webapp/webapp` and fail.

```sh
cd citrate-comms
vercel --prod --yes --archive=tgz
```

`--archive=tgz` is required: the repo root is a large Rust monorepo and an
un-archived upload exceeds Vercel's 15k-file limit. The root `.vercelignore`
excludes the Rust workspace and docs so only the `webapp/` tree is uploaded.
(`.vercel/` — the local project link — is gitignored; recreate it with
`vercel link` if missing.)

## Environment variables

Env vars live in the Vercel project (Production/Preview scopes), not in git.

- The Postgres vars (`DATABASE_URL`, `DATABASE_URL_UNPOOLED`, `POSTGRES_URL`, …)
  are **Neon integration-managed**. `vercel env pull` returns them **empty** even
  though they're set and available at runtime — so you cannot run migrations
  locally against prod without the real string. (Non-integration vars like the
  Blob/KV tokens pull normally.)
- `CRON_SECRET` (Sensitive, Production) authorizes the import-tick cron. Vercel
  Cron automatically sends it as `Authorization: Bearer $CRON_SECRET`. Rotate with
  `printf %s "$(openssl rand -hex 32)" | vercel env add CRON_SECRET production`,
  then redeploy (env changes only apply to new deployments).

## Applying migrations to prod

Because the prod `DATABASE_URL` isn't retrievable locally, run the migrator
**inside the Vercel build**, where the real secret is injected. Temporarily add
to `package.json` (leave uncommitted — `vercel --prod` uploads the working tree):

```json
"vercel-build": "node scripts/db-migrate.mjs && next build"
```

Deploy, confirm `migrations applied` in `vercel inspect --logs <url>`, then
**remove `vercel-build` again**. This is mandatory: `DATABASE_URL` is scoped
`Preview, Production`, so leaving `vercel-build` in would make every *preview*
build migrate the *production* database. Migrations are drizzle-journal-tracked
and additive, so reruns are safe.
