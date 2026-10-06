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
pnpm exec wrangler secret put BETTER_AUTH_SECRET --name threatsieve-api-staging
# Generate a cryptographically random value of at least 32 characters.
pnpm exec wrangler secret put THREATFOX_AUTH_KEY --name threatsieve-api-staging
pnpm exec wrangler secret put URLHAUS_AUTH_KEY --name threatsieve-api-staging
```

Generate the deployment config first with the deployment script's config-only mode described in `pnpm exec tsx scripts/deploy.ts --help`, then apply migrations before deploying traffic. Never commit generated credentials, `.dev.vars`, `.env.local`, real tenant bootstrap artifacts or raw customer intelligence.

Existing installations must apply all migrations through `0007_last_admin.sql` before running this release. Migration 0006 preserves existing users, tenant IDs and memberships while adding Better Auth tables; migration 0007 protects the final admin with D1 triggers. Migration 0005 preserves legacy exports and adds assessment revisions. Local `pnpm db:migrate` applies it to the development database.

## Release

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm eval
pnpm security
pnpm build
pnpm exec tsx scripts/deploy.ts
```

`pnpm exec tsx scripts/deploy.ts --production` requires `THREATSIEVE_PRODUCTION_RELEASE=approved`. In CI this belongs to a protected production environment with required reviewers. Configure the relevant staging/production resource variables and Cloudflare secrets in GitHub environments. Main-branch deployment runs only after checks and when deployment has explicitly been enabled for that repository.

Next.js 16 deploys via the OpenNext Cloudflare adapter. Better Auth sessions are proxied through the same-origin web handler. Production never uses `DEVELOPMENT_API_KEY`; provision the first administrator, then use Forgot password to establish that account’s password. Invite additional members in Team & access. See [authentication](authentication.md).

Verify a sending domain with Cloudflare Email Service before enabling invitations. Set `THREATSIEVE_AUTH_EMAIL_FROM` when generating deployment configuration to choose the sender; it updates both `AUTH_EMAIL_FROM` and the `EMAIL` binding’s allowed sender. The current production sender is `threatsieve@yumait.com.au`. No separate email API key is needed. Never enable live email delivery in automated tests.

## Acceptance checks

Verify `/health` and `/ready`; provision two distinct tenants; prove private telemetry is inaccessible across them; sync MITRE then MISP then required indicator feeds; classify a known source-backed indicator through real Clef; verify full raw distributions and escalation; confirm/reject from the browser; download STIX; receive a bundle in OpenCTI. Test queues, DLQ replay and failure recovery in the target account. Local unit tests do not substitute for these acceptance checks.

Set edge rate/body limits, log retention, alerting, billing alerts, and provider polling schedules appropriate to your plan. Load-test expected feed sizes and AI budgets. Keep Vectorize disabled until the index is populated; graph candidate retrieval continues independently.

## Cloudflare production verification

The hosted workspace is [ThreatSieve](https://threatsieve-web-production.yuma-it.workers.dev), with the [API health endpoint](https://threatsieve-api-production.yuma-it.workers.dev/health). Authentication is required for intelligence endpoints. Production has no synthetic demo seed.

The web Worker calls the API using its `THREATSIEVE_API` HTTP service binding. The release script binds it to the matching stage's API Worker. Direct same-account `workers.dev` fetches can return Cloudflare error 1042; local Node development continues using `API_ORIGIN`.

After provisioning a database and generating the release configuration, create an administrator without printing its key:

```sh
THREATSIEVE_WRANGLER_CONFIG=wrangler.deploy.local.json \
  pnpm exec tsx scripts/tenant.ts 'Your organisation' admin@example.com --remote
```

The one-time key is written to `artifacts/tenant-credentials.local.json` with owner-only permissions. Store it in your secret manager for integration API access. Browser sign-in uses the administrator email and a password established through Forgot password. The bootstrap script resolves the `DB` binding, so it works with stage-specific database names. Never run the synthetic demo seed against production.

The production acceptance check on 2026-10-06 exercised real Clef-flash and Clef escalation, persisted full distributions, exported STIX, created a secure browser session, and opened operations, sources, bulk analysis, clusters and inventory without browser exceptions. `example.com` returned unknown with no ATT&CK or actor assertion. Feed backfills run asynchronously; a successful sync request means queued, not that normalization has finished. ThreatFox and URLhaus require their own secrets before they can sync. Vectorize remains disabled until knowledge embeddings are populated.

The EC2-hosted OpenCTI integration is documented in [OpenCTI hosting](opencti-hosting.md). ThreatSieve itself has no EKS dependency.

The Better Auth release applies migrations 0006–0007 and preserves existing organization membership and API keys. Production checks verified API-key compatibility (200), anonymous session lookup (200 with null), anonymous tenant access (401), disabled key-to-browser-session exchange (401), rejected foreign-Origin login (403), and rendered sign-in/recovery screens without browser exceptions. Invitation delivery and password resets are exercised with a captured email binding in the offline suite; live mailbox delivery is not asserted by those tests.
