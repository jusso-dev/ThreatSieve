# ThreatSieve

**Turn raw threat data into evidence-backed threat decisions.**

ThreatSieve is a TypeScript-first intelligence pipeline and analyst workspace built on Cloudflare Workers, D1, R2, Queues, Workers AI and Vectorize. It uses Clef typed decisions at bounded classification points. It is not a chatbot, a generative attribution engine or a blocking system.

![ThreatSieve operations workspace with explicitly labelled demonstration intelligence](docs/images/operations.png)

[View the complete screenshot gallery](#screenshots). [Current production readiness and remaining acceptance](docs/readiness.md).

## Run locally

Requirements: Node.js 22.22.3+ (22.x) or 24.8+, pnpm 10, and a Cloudflare account with Workers AI access for live classification.

```sh
pnpm install
pnpm bootstrap
pnpm dev
```

Open **http://127.0.0.1:3000**. The API listens on **http://127.0.0.1:8787**. Bootstrap applies local migrations and seeds six explicitly synthetic scenarios plus example requirements, investigations, watchlists, collections, reports and a paused playbook. It creates a random local API key in `credentials.local.json` and a development-only server credential in `apps/web/.env.local`. Both files are ignored by Git. The frontend uses this credential only when `NODE_ENV=development`; production requires sign-in.

The seeded UI works without calling AI. **New assessments call real Workers AI**, including during local Wrangler development. Authenticate with `pnpm exec wrangler login` before making live assessments. There is no silent substitute for an unavailable classifier. Copy `.dev.vars.example` to `.dev.vars` and supply ThreatFox and URLhaus keys to enable those feeds. MITRE, MISP Galaxy, Feodo and CISA KEV require no application credential.

```sh
pnpm --silent cli assess example.com --json
pnpm --silent cli assess-file indicators.csv --json
pnpm --silent cli feeds sync mitre --json
pnpm --silent cli feeds sync misp --json
pnpm --silent cli feeds sync threatfox --json
pnpm --silent cli actor 'Fancy Bear' --json
pnpm --silent cli attack T1071.001 --json
```

Sync MITRE first, then MISP, then indicator feeds so canonical knowledge is available for candidate retrieval. Feed imports are asynchronous. Check source status in the UI. `example.com` with no supporting intelligence should produce an **unknown** assessment, not an invented malicious verdict.

## Intelligence operations platform

- Intelligence requirements with collection criteria, evidence-linked coverage, freshness, confidence and explicit gaps.
- Collaborative investigations with hypotheses, tasks, cited intelligence, revision checks and timestamped decisions.
- Canonical dossiers with separate, explainable threat, confidence, relevance and priority scores.
- First-class private sightings, watchlists, matched intelligence, notifications, collections and authored reports.
- Filtered bounded graph exploration, shortest visible connection paths, evidence pivots and Cmd/Ctrl+K search.
- Source reliability ratings, tenant source policy, sync history, quarantined records and replay.
- Event playbooks using the existing outbox/queues, with execution history and approved webhook delivery.
- Tenant-authenticated TAXII 2.1 collection snapshots and MISP event exchange.
- Asynchronous STIX collection packages with resumable queue processing, checksummed parts, access revalidation and temporary-copy expiry.
- Six required source adapters with Zod validation, deterministic identities, source provenance and R2 archival.
- D1 graph storage, actor aliases, bounded graph candidates and configurable Vectorize retrieval with batched public-knowledge indexing.
- Clef-flash → confidence gate → Clef escalation. Full question distributions and candidate sets are retained.
- Behaviour-gated ATT&CK mappings, conservative actor associations, structured confidence factors and customer relevance.
- Better Auth accounts, verified email, team invitations, admin/analyst/viewer roles, password recovery, authenticator MFA with single-use recovery codes, scoped API keys and tenant isolation.
- Accessible toast notifications and actionable inline messages throughout analyst workflows.
- Filterable analyst queue with server-side sorting, bookmarkable filters and personal saved triage views.
- Intelligence library with source/category filters, canonical aliases and MITRE-ID search.
- Investigation evidence search/timeline, directed graph and relationship list, ATT&CK-to-evidence pivots and defanged copying.
- Confirm/reject/modify/investigate, bulk upload, expandable source health, clusters and environment profile.
- Asynchronous processing, D1 outbox, job leases, retry/dead-letter handling and replay.
- STIX 2.1 export and a Python OpenCTI connector using `OpenCTIConnectorHelper.send_stix2_bundle`.
- Optional provider adapters for OTX, VirusTotal, GreyNoise, TAXII, STIX and MISP; disabled unless explicitly configured.
- Offline evaluation metrics and browser/integration/security tests.

[Analyst workflows and boundaries](docs/intelligence-operations.md) · [Automation](docs/automation.md) · [TAXII and MISP](docs/taxii-misp.md) · [Enterprise architecture](docs/enterprise-upgrade.md)

## Commands

| Command                                               | Purpose                                                          |
| ----------------------------------------------------- | ---------------------------------------------------------------- |
| `pnpm dev`                                            | API Worker and Next.js development servers                       |
| `pnpm bootstrap`                                      | Local migrations and synthetic demo seed                         |
| `pnpm test`                                           | Offline unit and D1 integration tests                            |
| `pnpm test:e2e`                                       | Isolated full-stack tests using tester-army/e2e                  |
| `pnpm lint`                                           | TypeScript/React lint checks                                     |
| `pnpm typecheck`                                      | Strict backend and frontend types                                |
| `pnpm build`                                          | Worker dry-run bundle and Next.js production build               |
| `pnpm eval`                                           | Evaluation fixture self-check; emits `artifacts/evaluation.json` |
| `pnpm security`                                       | Repository security checks                                       |
| `pnpm run deploy`                                     | Configured staging deployment; see deployment guide              |
| `pnpm tenant:create 'Organisation' admin@example.com` | Provision a local tenant and one-time key                        |

For browser tests, run `pnpm exec e2e-web install chromium` once, then `pnpm test:e2e`. The suite starts its own production web build and ephemeral Workers/D1/R2/Queues environment; no bootstrap, Cloudflare login, feed credentials or model API key is needed. See [end-to-end testing](docs/e2e.md) for coverage and diagnostics. The earlier Playwright regressions remain available as `pnpm test:playwright` against the local demo (CI starts that demo automatically). Tests never use live intelligence APIs. `pnpm eval --current current.json --candidate candidate.json` compares measured predictions. Default fixture metrics are **not a claim about Clef accuracy**.

## Production deployment

Hosted workspace: **[ThreatSieve on Cloudflare](https://threatsieve-web-production.yuma-it.workers.dev)**. Sign in with your email and password. Existing administrators use **Forgot password** once to set their password. Invite colleagues from **Team & access**; see [accounts and teams](docs/authentication.md). OpenCTI runs separately on a private EC2 host; see [access and operations](docs/opencti-hosting.md).

See [deployment](docs/deployment.md) for resource provisioning, migration review, secrets, staging and protected production releases. The checked-in D1 identifier is local-only and the deployment script requires a real ID. Nothing deploys to a Cloudflare account merely by installing or building the project.

Commercial readiness still requires a deployment-specific review: provider redistribution agreements, measured model evaluations, customer SSO, retention policy, operational alerting, load tests and OpenCTI/Workers AI acceptance tests in the target environment. This repository provides an operational intelligence workspace and explicit scale/security boundaries; it does not claim those operational acceptance checks have happened automatically.

## Design constraints

Models select existing candidates and cannot create intelligence entities. An ATT&CK relationship from malware to a technique is a candidate, not proof that an indicator exhibited that behaviour. Actor similarity is not attribution. Private telemetry is tenant-scoped. Exports omit non-redistributable evidence by default. All remediation actions are recommendations.

## Screenshots

Screenshots use explicitly synthetic demonstration intelligence.

### Intelligence requirements

![Requirements prioritized by coverage, freshness, confidence and linked evidence](docs/images/requirements.png)

### Requirement dossier

![Intelligence question, collection criteria, supporting evidence and explicit gaps](docs/images/requirement-detail.png)

### Collaborative investigation

![Analyst hypothesis, tasks, pinned intelligence, graph and decision history](docs/images/analyst-investigation.png)

### Canonical entity dossier

![Separate threat, confidence, relevance and priority factors with source provenance](docs/images/entity-dossier.png)

### Watchlists

![Tenant watchlists with deterministic collection criteria](docs/images/watchlists.png)

### Collections

![Curated intelligence packages for controlled distribution](docs/images/collections.png)

### Intelligence report

![Analyst-authored intelligence report with original evidence references](docs/images/intelligence-report.png)

### Automation

![Event-driven playbooks with bounded actions and execution history](docs/images/automation.png)

### Source operations

![Feed health, collection history, source ratings, policy and provenance](docs/images/source-operations.png)

### System health

![Feed freshness, pipeline backlog, classification allowance and OpenCTI delivery monitoring](docs/images/system-health.png)

Captured from the running application with the labelled synthetic demo dataset. These images show the desktop workspace and responsive mobile layout; displayed probabilities are demonstration values.

### Investigation, evidence and intelligence graph

![Investigation showing model probabilities, evidence provenance, the intelligence graph and analyst decisions](docs/images/investigation.png)

### Intelligence library

![Intelligence library with category navigation, aliases, source filtering and canonical entity records](docs/images/intelligence-library.png)

| Mobile library                                                                                                                         | Mobile investigation                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| <img src="docs/images/intelligence-library-mobile.png" width="320" alt="Mobile intelligence library with accessible category filters"> | <img src="docs/images/investigation-mobile.png" width="320" alt="Responsive evidence, relationships and analyst investigation"> |

### Bulk analysis

![Bulk analysis with pasted indicators and CSV, JSON or STIX file upload](docs/images/bulk.png)

### Intelligence sources

![Intelligence sources with sync controls, feed status and redistribution information](docs/images/sources.png)

### Emerging clusters

![Unknown threat cluster with source-backed observable membership and no forced actor attribution](docs/images/clusters.png)

### Customer environment

![Customer technology profile used to calculate threat relevance](docs/images/inventory.png)

### Workspace sign-in

![Better Auth email and password sign-in with account recovery](docs/images/sign-in.png)

### Team members and invitations

![Account security with verified authenticator protection and session revocation](docs/images/account-security.png)

![Team management with role controls, invitations and toast notifications](docs/images/team-access.png)

<img src="docs/images/team-mobile.png" width="320" alt="Responsive team management on mobile">

### Mobile operations and navigation

| Threat operations                                                                                                                            | Navigation drawer                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| <img src="docs/images/operations-mobile.png" width="320" alt="Mobile threat operations with priority intelligence and the observable queue"> | <img src="docs/images/mobile-navigation.png" width="320" alt="Mobile navigation drawer extending to the bottom of the viewport"> |

## Documentation

[TIP UX review and design decisions](docs/tip-ux-review.md) · [All 244 reference entries](docs/research/catalogue.md) · [Accounts and teams](docs/authentication.md) · [Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) · [Classification](docs/classification.md) · [Confidence](docs/confidence-model.md) · [Sources](docs/intelligence-sources.md) · [Data model](docs/data-model.md) · [API](docs/api.md) · [OpenCTI](docs/opencti.md) · [Deployment](docs/deployment.md) · [Commercial architecture](docs/commercial-architecture.md)

![Queued STIX collection package with download manifest](docs/images/collection-export.png)
