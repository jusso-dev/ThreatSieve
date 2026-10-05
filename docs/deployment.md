# Deployment

Use separate Cloudflare resources for staging and production. The repository's root Wrangler configuration supports local development; its D1 identifier is deliberately not a production resource. The deployment script refuses to run without real configuration.

## Provision native resources

For staging (use the same naming pattern with `production` for production):

```sh
pnpm exec wrangler d1 create threatsieve-staging
pnpm exec wrangler r2 bucket create threatsieve-archive-staging
pnpm exec wrangler vectorize create threatsieve-intel-staging --dimensions=768 --metric=cosine
pnpm exec wrangler queues create intel-dead-letter-staging
pnpm exec wrangler queues create intel-ingest-staging
pnpm exec wrangler queues create intel-normalise-staging
pnpm exec wrangler queues create intel-enrich-staging
pnpm exec wrangler queues create intel-correlate-staging
pnpm exec wrangler queues create intel-classify-staging
pnpm exec wrangler queues create intel-export-staging
```

Set `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `THREATSIEVE_D1_ID`, `THREATSIEVE_WEB_ORIGIN` and `THREATSIEVE_API_ORIGIN`. Use origin URLs without trailing paths. Worker names become `threatsieve-api-staging` and `threatsieve-web-staging`. Queue/resource names are stage-suffixed. The generated configs are ignored `.local.json` files.

## Migrations and secrets

Review the SQL migration set before applying it to remote D1. Take a D1 backup/Time Travel recovery checkpoint according to your organisation's retention policy. Apply additive migrations as a separate release step. The deployment command does not automatically apply migrations.

```sh
pnpm exec wrangler d1 migrations apply threatsieve-staging --remote --config wrangler.deploy.local.json
pnpm exec wrangler secret put THREATFOX_AUTH_KEY --name threatsieve-api-staging
pnpm exec wrangler secret put URLHAUS_AUTH_KEY --name threatsieve-api-staging
```

Generate the deployment config first with the deployment script's config-only mode described in `pnpm deploy --help`, then apply migrations before deploying traffic. Never commit generated credentials, `.dev.vars`, `.env.local`, real tenant bootstrap artifacts or raw customer intelligence.

Existing installations must apply `0005_review_and_exports.sql` before running this release. It preserves legacy export records and adds assessment revisions, versioned export storage and query indexes. Local `pnpm db:migrate` applies it to the development database.

## Release

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm eval
pnpm security
pnpm build
pnpm deploy
```

`pnpm deploy --production` requires `THREATSIEVE_PRODUCTION_RELEASE=approved`. In CI this belongs to a protected production environment with required reviewers. Configure the relevant staging/production resource variables and Cloudflare secrets in GitHub environments. Main-branch deployment runs only after checks and when deployment has explicitly been enabled for that repository.

Next.js 16 deploys via the OpenNext Cloudflare adapter. Web sessions are proxied to the API through a same-origin route handler. Production never uses `DEVELOPMENT_API_KEY`; provision tenant membership and a scoped bootstrap key, then sign in. Prefer a production identity provider/SSO integration before broad multi-user commercial rollout.

## Acceptance checks

Verify `/health` and `/ready`; provision two distinct tenants; prove private telemetry is inaccessible across them; sync MITRE then MISP then required indicator feeds; classify a known source-backed indicator through real Clef; verify full raw distributions and escalation; confirm/reject from the browser; download STIX; receive a bundle in OpenCTI. Test queues, DLQ replay and failure recovery in the target account. Local unit tests do not substitute for these acceptance checks.

Set edge rate/body limits, log retention, alerting, billing alerts, and provider polling schedules appropriate to your plan. Load-test expected feed sizes and AI budgets. Keep Vectorize disabled until the index is populated; graph candidate retrieval continues independently.
