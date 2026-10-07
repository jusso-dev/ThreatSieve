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
pnpm exec wrangler d1 migrations apply threatsieve-staging --remote --config wrangler.staging.local.json
pnpm exec wrangler secret put BETTER_AUTH_SECRET --name threatsieve-api-staging
# Generate a cryptographically random value of at least 32 characters.
pnpm exec wrangler secret put THREATFOX_AUTH_KEY --name threatsieve-api-staging
pnpm exec wrangler secret put URLHAUS_AUTH_KEY --name threatsieve-api-staging
```

Generate the deployment config first with the deployment script's config-only mode described in `pnpm exec tsx scripts/deploy.ts --help`, then apply migrations before deploying traffic. Never commit generated credentials, `.dev.vars`, `.env.local`, real tenant bootstrap artifacts or raw customer intelligence.

Existing installations must apply all migrations through `0018_collection_packages.sql` before running this release. Migration 0008 adds personal saved views and browsing/sorting indexes without changing existing intelligence. Migration 0006 preserves existing users, tenant IDs and memberships while adding Better Auth tables; migration 0007 protects the final admin with D1 triggers. Migration 0005 preserves legacy exports and adds assessment revisions. Local `pnpm db:migrate` applies these to the development database.

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

## Enterprise workspace release

Migrations 0009–0014 add scoped workspace objects, sightings, source ratings, durable change events, matches, automation execution history, TAXII snapshots, source policy and relationship assertion history. They are additive; no existing intelligence tables are dropped. Record a D1 Time Travel bookmark before applying them. Deploy the API after migrations, then the web Worker. Retain the previous Worker version for application rollback; additive tables can remain in place. Do not seed production.

New operations jobs share the existing ingest queue and its dead-letter controls. Review queue age and D1 storage growth after enabling broad watchlists/requirements. Initial matching is asynchronous and can process many existing records. The pipeline does not claim that an arbitrary million-record workload has been load-tested. Configure retention for archives, event histories, old TAXII generations and execution records according to contractual requirements before commercial rollout.

Optional source and integration settings are documented in [TAXII/MISP](taxii-misp.md) and [automation](automation.md). Keep credentials and integration target configuration in encrypted Worker environment values; the repository contains no active webhook targets.

## Operational reliability release

Migrations 0015–0016 add outbox reservations, delivery generation recovery, operational indexes and tenant-scoped connector heartbeats. Record a D1 Time Travel bookmark before applying them, deploy the API, then the web Worker. The new **System health** page and least-privilege external probe are documented in [production operations](operations.md). Recovery preserves committed intelligence and does not claim that an accepted queue message is a completed source sync.

## Readiness release

See the [current readiness register](readiness.md), [restore verification](recovery.md) and [queued collection packages](collection-packages.md). Migration 0017 adds Better Auth second-factor storage; 0018 adds disposable export snapshots and queue indexes. Both are additive. Staging writes `wrangler.staging.local.json`; production retains `wrangler.deploy.local.json` so one environment cannot overwrite the other's configuration.

Create the Vectorize metadata index before backfill: `wrangler vectorize create-metadata-index threatsieve-intel-staging --property-name entityType --type string` (use the production index for production). An administrator can queue `/v1/ops/vectorize/backfill` while retrieval is disabled and inspect `/v1/ops/vectorize`. Set `THREATSIEVE_VECTORIZE_ENABLED=true` only after coverage and live retrieval checks, and persist it in the matching GitHub environment for future releases.

The production workflow accepts a full commit SHA with a successful main-branch CI run. The GitHub production environment restricts deployment to main and requires owner review. Automatic staging remains disabled until a dedicated, resource-scoped `CLOUDFLARE_API_TOKEN` is installed in GitHub; local Wrangler OAuth is never copied into CI secrets. Set `ENABLE_STAGING_DEPLOY=true` only after configuring that credential. Custom domains and their trusted auth origins require an explicitly selected domain.

After an account enables MFA, do not roll the API back to a release that lacks MFA enforcement. Prefer a forward fix or disable password sign-in at the edge while recovering. Additive migration rollback alone does not preserve second-factor protection.

The tenant bootstrap CLI refuses to overwrite an existing one-time key file. Set `THREATSIEVE_CREDENTIALS_NAME=staging-tenant-credentials.local.json` when provisioning a separate staging workspace.

On 7 October 2026, the public knowledge backfill and live filtered retrieval checks completed: 5,243 vectors are present in production. Semantic candidate retrieval is now enabled in staging and production, including the corresponding GitHub environment variable. The earlier disabled-state record above describes the 6 October deployment. See the readiness register for current deployed versions, acceptance results and outstanding operational dependencies.
