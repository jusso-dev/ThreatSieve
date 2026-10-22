# API v1

Authenticate integrations with `Authorization: Bearer $THREATSIEVE_API_KEY`. Browser users sign in with Better Auth email/password at `/api/auth/sign-in/email` through the same-origin web proxy. Eight-hour HttpOnly sessions derive permissions from current tenant membership on every request. Session mutations require the configured web Origin. See [accounts and teams](authentication.md).

```sh
curl -X POST http://127.0.0.1:8787/v1/assess \
  -H "Authorization: Bearer $THREATSIEVE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"observable":"example.com"}'
```

`POST /v1/assess` returns a versioned assessment synchronously. Optional `type` overrides safe type detection. An unrecognised or ambiguous value returns 422. Provider/classifier failure is an error, never a fabricated assessment.

| Routes                                                                                            | Scope                |
| ------------------------------------------------------------------------------------------------- | -------------------- |
| `POST /v1/assess`, `POST /v1/assess/bulk`, `POST /v1/uploads?format=text` (also csv, json, stix)  | assessment:write     |
| `GET /v1/assessments`, `GET /v1/assessments/:id`                                                  | assessment:read      |
| `POST /v1/assessments/:id/{confirm,reject,modify,investigate,reclassify}`                         | assessment:write     |
| `GET /v1/assessments/:id/stix`                                                                    | assessment:read      |
| `GET /v1/observables/:id`                                                                         | intel:read           |
| `POST /v1/lookup` ([bulk lookup](#bulk-lookup))                                                   | intel:read           |
| `GET /v1/actors`, `/v1/malware`, `/v1/campaigns`, `/v1/attack/techniques` and their `/:id` routes | intel:read           |
| `GET /v1/search?q=`, `GET /v1/graph/:id?depth=1..3`                                               | intel:read           |
| `GET /v1/clusters`, `GET /v1/clusters/:id`                                                        | intel:read           |
| `GET /v1/feeds`, `GET /v1/feeds/:id/health`                                                       | feeds:read           |
| `POST /v1/feeds/:id/sync`                                                                         | feeds:write          |
| `POST /v1/relationships/:id/{confirm,reject}`                                                     | assessment:write     |
| `GET /v1/jobs/:id`, `GET /v1/exports`, `GET /v1/exports/:id`                                      | assessment:read      |
| `POST /v1/jobs/:id/replay`                                                                        | admin                |
| `GET /v1/environment`                                                                             | intel:read           |
| `PUT /v1/environment`                                                                             | admin                |
| `POST /v1/observations`                                                                           | assessment:write     |
| `POST /v1/api-keys`, `DELETE /v1/api-keys/:id`, `GET /v1/ops`                                     | admin                |
| `POST /v1/ingest` ([ingest API](ingest.md))                                                       | ingest:write         |
| `GET /v1/ingest/:id`, `GET /v1/ingest/metrics`                                                    | ingest:read          |
| `GET /v1/me`                                                                                      | authenticated        |
| `GET /health`, `GET /ready`, `GET /openapi/ingest.json`                                           | public, minimal data |

Bulk JSON takes `{ "observables": ["example.com", {"observable":"192.0.2.5","type":"ipv4"}] }`. Uploads take a raw UTF-8 body and explicit format. CSV needs `observable` (or `indicator`) and optional `type` headers. A 202 response includes the tenant-scoped job ID. Poll `/v1/jobs/:id`; stages report ingestion and classification separately. `pipeline_status` is `running`, `complete`, or `failed` across all child pages and stages; stop polling on a terminal value. `totals` counts processed and rejected inputs. Limits are 16 MiB and 100,000 items per upload.

Bulk endpoints accept an optional `Idempotency-Key` (1–200 characters). Reuse it when retrying the same parsed inputs: concurrent requests converge on one tenant-scoped job and one audit record. A different body under the same key returns 409 `IDEMPOTENCY_CONFLICT`. Reservations persist until operator cleanup; they do not expire automatically.

Feedback requires `{ "reason": "Validated against source evidence", "field": "assessment" }`. Include `expected_revision` from the assessment (`0` when absent) to protect against stale edits. The UI always supplies it; a stale or concurrent conflicting edit returns 409 `ASSESSMENT_CHANGED`. Reload the assessment before retrying. Modify can include a structured `value`; original model values remain available and the analyst overlay is stored separately. Feedback invalidates classification cache entries, creates an audit event, increments the revision and queues a revised STIX export in one transaction. Confirmed decisions leave the review queue; rejected, modified and needs-investigation decisions remain until resolved. Tenant relationship rejection removes the edge from subsequent graph/candidate retrieval for that tenant and invalidates its classification cache.

Assessments retain `schema_version`, observable, maliciousness probability/classification, role, confidence factors, ATT&CK mappings, potential actor associations, structured customer relevance, recommendations, evidence, provenance and full runs. `demo: true` labels synthetic records. Do not interpret `actors` as verified attribution or automatically execute `recommended_actions`.

Errors use `{ "error": { "code", "message", "request_id" } }`. Validation errors can also include field issues. Common codes: UNAUTHORIZED, FORBIDDEN, NOT_FOUND, VALIDATION_ERROR, INVALID_OBSERVABLE, RATE_LIMITED, AI_BUDGET_EXHAUSTED, FEED_DISABLED, FEED_NOT_SYNCABLE, TOO_MANY_OBSERVABLES. Every 429 carries `Retry-After` in seconds; rate-limit windows are calendar minutes.

Entity lists default to 50 and cap at 100 records. Graph depth caps at three, nodes at 100 and edges at 200. The graph response indicates truncation. Intelligence search does exact canonical/alias lookup plus bounded prefix search; it is not a semantic answer generator.

## Operational recovery

`GET /v1/feeds/:id/jobs` lists outstanding global feed jobs. `POST /v1/feeds/:id/jobs/:jobId/replay` requires `feeds:write` and requeues only failed jobs belonging to that feed. Tenant bulk jobs use `/v1/jobs/:id/replay` with tenant-scoped `admin`. Poison messages with invalid job schemas are quarantined in R2.

`GET /v1/entities/:id` returns a visible entity, all retained source provenance, and bounded visible relationships. Actors include a source-weighted fingerprint. Assessment pagination uses opaque composite cursors to preserve records with equal creation timestamps.

`GET /v1/assessments` accepts `view=all|attention|review`, `q`, `limit` and `cursor`. Filtering is performed before pagination. Responses include tenant-wide `summary` counts and the top three attention items in `priority`; those counts do not depend on the current page. Invalid cursors return 400 `INVALID_CURSOR`.

Better Auth browser routes include sign-in, sign-up, sign-out, email verification, password reset and the organization plugin’s invitation/member endpoints. API Worker routes use `/auth/*`; the web proxy exposes `/api/auth/*`. Organization creation/deletion are disabled. The legacy `/v1/session` key exchange is development-only; production sign-out uses `POST /api/auth/sign-out`.

## Analyst library and saved triage views

`GET /v1/entities` requires `intel:read`. Parameters: `q` (literal name/alias/external-ID prefix, max 256 characters), `type` (entity type), `source` (source ID), `limit` (1–100, default 50), `cursor` (opaque). Returns `{data, next_cursor}` ordered by case-insensitive name then ID. Visibility is applied before pagination. Existing `/v1/actors`, `/v1/malware`, `/v1/campaigns` and `/v1/attack/techniques` retain their ID-based cursor format and now consistently enforce visibility.

`GET /v1/assessments` also accepts `severity`, `classification`, `observable_type`, `status`, `min_confidence` (0–1), `observed` (`yes`/`no`) and `sort` (`newest`, `oldest`, `confidence`, `relevance`). The wire value `sort=relevance` orders by operational urgency (UI label "Highest operational urgency"), not customer-relevance score. Filters apply to the whole tenant dataset. Classification uses the analyst override when present. Use the returned opaque cursor unchanged; reset it when filters or sort change. Historical newest-first cursors remain supported. Summary counts are workspace-wide, independent of table filters.

Saved views require `assessment:read` and are personal to the authenticated user within the active tenant:

- `GET /v1/saved-views`: list up to 50 saved views.
- `POST /v1/saved-views`: `{name, filters}`. Name is 1–60 characters; filters follow the validated assessment query schema. An existing name updates that view. Returns 201 on success, 409 when the limit prevents creation.
- `DELETE /v1/saved-views/:id`: delete an owned view; foreign IDs return 404.

Saved-view writes are audited. URLs and saved filters convey no authorization. Browser links still require a valid session and tenant membership.

## Enterprise workspace APIs

All routes below require the existing authenticated tenant context. Reads use `intel:read`; writes use `assessment:write`. Playbook changes and source trust policy additionally require `admin`. No route accepts an arbitrary tenant override.

| Route                                      | Behavior                                                                        |
| ------------------------------------------ | ------------------------------------------------------------------------------- |
| `GET/POST /v1/requirements`                | Browse/create intelligence requirements                                         |
| `GET/POST /v1/investigations`              | Browse/create collaborative investigations                                      |
| `GET/POST /v1/watchlists`                  | Browse/create deterministic watches                                             |
| `GET/POST /v1/collections`                 | Browse/create curated collections                                               |
| `GET/POST /v1/reports`                     | Browse/create authored reports                                                  |
| `GET/POST /v1/playbooks`                   | Browse/create bounded event automation                                          |
| `GET/PUT /v1/{module}/:id`                 | Detail/revision-protected edit                                                  |
| `POST /v1/{module}/:id/notes`              | Append a note or analyst decision                                               |
| `GET /v1/{module}/:id/export?format=`      | JSON, CSV, STIX, MISP or printable HTML; excludes playbooks                     |
| `GET /v1/workspace/:id/matches`            | Paginated source/evidence-backed match suggestions                              |
| `GET /v1/workspace/search?q=`              | Federated tenant workspace search                                               |
| `GET /v1/workspace/references?type=&q=`    | Authorized citation/pin selection                                               |
| `GET /v1/workspace/reference-labels?refs=` | Bounded batch reference labels                                                  |
| `GET /v1/workspace/members`                | Owners/collaborators available within the tenant                                |
| `POST /v1/observables`                     | Create a private normalized observable without classifying it                   |
| `GET/POST /v1/sightings`                   | Browse/record observations with idempotent source event IDs                     |
| `GET /v1/entities/:id/dossier`             | Canonical intelligence, factors, relationships, evidence, sightings and history |
| `GET /v1/entities/:id/timeline?days=`      | 1/7/30/90/365/all retained event windows                                        |
| `GET /v1/evidence/:id`                     | Authorized evidence and provenance                                              |
| `GET /v1/notifications`                    | Workspace match/action notifications                                            |
| `POST /v1/notifications/:id/read`          | Personal read receipt; `intel:read` permitted                                   |
| `GET /v1/playbooks/:id/executions`         | Bounded execution history and queued-action IDs                                 |
| `GET /v1/integrations`                     | Approved integration IDs/names, never credentials                               |
| `GET /v1/feeds/:id/quality`                | Collection metrics, sampled reviews, errors, evidence and licensing             |
| `PUT /v1/feeds/:id/rating`                 | Workspace Admiralty reliability/credibility rating with rationale               |
| `PUT /v1/feeds/:id/policy`                 | Include/exclude a source for this tenant's new assessments                      |
| `GET /v1/source-ratings`                   | Source-quality labels for evidence views                                        |
| `POST /v1/collections/:id/publish`         | Materialize an explicit TAXII snapshot                                          |
| `GET /v1/collections/:id/publication`      | Snapshot revision/time/object count                                             |

Browse endpoints accept `q`, `status`, `cursor`, and `limit` (1–100). Replies contain `data` and `next_cursor`. Workspace IDs use UUIDs; automation-created investigations use stable action identities. All clients should treat IDs as opaque strings.

Creation examples:

```json
{
  "title": "Actively exploited technologies",
  "question": "Which actively exploited vulnerabilities affect our environment?",
  "priority": "high",
  "status": "active",
  "criteria": { "technologies": ["FortiOS"], "sourceIds": ["cisa-kev"] },
  "references": []
}
```

```json
{
  "observable": { "observable": "192.0.2.4" },
  "source": "dns",
  "externalId": "sensor-event-42",
  "observedAt": "2026-10-06T01:00:00.000Z",
  "asset": "Example workstation",
  "count": 3,
  "confidence": 0.9,
  "context": "Synthetic documentation example"
}
```

Updates require `{"object": {...complete object input...}, "expected_revision": 1, "reason": "Why the analyst changed it"}`. Creation records the authenticated author. Revision conflicts return 409 and do not partially update links/history. Oversized operational JSON requests return 413 at 128 KiB. Unavailable and cross-tenant records both return 404. Export HTML escapes text and disallows scripts; CSV escapes spreadsheet formulas.

Graph filters now accept `confidence` (0–1), `source`, `relationship`, `entityType`, `from` and `to` alongside depth. Responses include authorized `sightedEntityIds` and `truncated`.

TAXII protocol endpoints, content types and pagination are documented in [TAXII/MISP](taxii-misp.md). Structured schemas are in `packages/schemas/src/enterprise.ts`.

Entity tags are tenant-scoped: `POST /v1/entities/:id/tags` accepts `{ "tag": "priority-hunt", "operation": "add", "reason": "Hunt scope" }` (`remove` is also supported). Dossiers return `workspaceTags`. Automatic watchlist memberships appear in match results as `automatic_member`; `DELETE /v1/watchlists/:id/members/:entityId` removes that membership with an audit event. These mutations require `assessment:write`.

## Bulk lookup

`POST /v1/lookup` answers up to 500 observables from stored intelligence in one synchronous call. It is built for integrations such as [Foiled](foiled.md) that need context, not a new assessment. It never calls Workers AI or a paid model, and it does not create observables, assessments or audit events.

```sh
curl -X POST http://127.0.0.1:8787/v1/lookup \
  -H "Authorization: Bearer $THREATSIEVE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"observables":[{"type":"ipv4","value":"203.0.113.7"},{"type":"cve","value":"CVE-2099-0001"}],"include":["reputation","network","cve","relationships"]}'
```

- Scope `intel:read`. The route has its own rate-limit bucket: `LOOKUP_RATE_LIMIT` requests per minute per key (default 60) and five times that per tenant. Assessment traffic does not consume it.
- `type` is one of `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `cve`, `asn`. Values are normalised as for deduplication: lowercase domains, canonical IPv6, upper-case CVE IDs, `AS<number>`.
- `include` selects `reputation`, `network`, `cve` and `relationships`; it defaults to all four.
- More than 500 observables returns 413 `TOO_MANY_OBSERVABLES`. The body is limited to 4 MiB. An unsupported `type` is a 400 `VALIDATION_ERROR`.
- Duplicates (after normalisation) are answered once, in first-seen order. A value that fails normalisation gets its own result with `error.code` `INVALID_OBSERVABLE` and `found: false`; the rest of the request still succeeds.

Each result has:

| Field                    | Meaning                                                                                                                                                                                                                    |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`, `value`, `input` | Type, normalised value, and the first submitted spelling                                                                                                                                                                   |
| `found`                  | ThreatSieve holds at least one reputation, CVE or relationship fact, or a visible entity. Network context alone does not set it                                                                                            |
| `entity_id`              | The visible observable ID (`obs_…`), otherwise `null`                                                                                                                                                                      |
| `ttl_seconds`            | Shortest reuse time among contributing sources; 3600 when nothing is known; at most 300 while `pending_sources` is non-empty                                                                                               |
| `pending_sources`        | Rate-limited sources being fetched by a queued refresh, or waiting for the next lookup because this request's per-source cap was reached. Ask again after a short wait. Sources whose daily budget is spent are not listed |
| `reputation`             | `classification` (`malicious`, `suspicious`, `benign`, `unknown`), `score` and `confidence` (0–100 `dossier-v1` heuristics, `null` when unknown), `scanner` and `tags`. `null` for CVEs and when no evidence exists        |
| `network`                | `asn`, `as_org`, `prefix` (largest CIDR inside the announced range) and `country` from the IPtoASN dataset; for `asn` lookups `prefix` is `null`                                                                           |
| `cve`                    | NVD description, status, CVSS, CWE, references and affected products; CISA KEV listing; FIRST EPSS; OSV identifiers                                                                                                        |
| `relationships`          | Up to 25 visible relationships: `type` in lowercase with hyphens (`indicates`, `hosted-on`), `direction`, `assertion`, `confidence` 0–100, `source_id` and the other entity with `external_ids`                            |
| `sources`                | Every source behind a returned fact, with `license`, `redistributable`, `commercial_use` (`null` when unknown), tenant-adjusted `reliability`, `first_seen`, `last_seen`, `retrieved_at` and `source_url`                  |

Reputation classification is a fixed rule over source assertions: malicious and benign assertions together give `suspicious`; a malicious assertion gives `malicious`; a benign assertion or benign service gives `benign`; scanning activity alone gives `suspicious`. `score` and `confidence` are the [`dossier-v1`](confidence-model.md#dossier-scoring-dossier-v1) threat and confidence heuristics without customer context. Analyst assessments are not consulted. `scanner.source_id` names the first contributing scanner source, preferring GreyNoise, then CrowdSec.

Tenant source policy applies to every section: a source a tenant has excluded contributes no evidence, network, CVE or relationship fact, and is not refreshed for that tenant. Private observables of other tenants remain invisible. GreyNoise, CrowdSec and OSV answers are cached in `source_lookup_cache`, not in the shared graph, so a lookup does not make a value searchable by other tenants. GreyNoise and CrowdSec answers are cached per tenant, so another tenant's lookups, their timing and their pending state are never visible. OSV answers are public advisory data, cached once for all tenants and reported without `retrieved_at`.

A lookup uses a fixed number of D1 statements, independent of the number of observables: daily budgets are read in one query, cache misses are claimed in one statement per source, and refreshes are queued as one enrich-queue job per source. Queued refreshes retry with backoff; a refresh that still fails on its last attempt is cached as an error for 15 minutes and its budget unit is refunded. `redistributable` is true only when the source record allows redistribution and every contributing record was marked redistributable.

Results are deterministic for the same stored data and time; `as_of` is the response time. The recency part of `score` and `confidence` depends on the current time.

## Source licences on entity APIs

`GET /v1/actors`, `/v1/malware`, `/v1/campaigns` and `/v1/attack/techniques` add `source_licences` to every listed entity. Their `/:id` routes and `GET /v1/entities/:id` add it at the top level of the response. Each entry has the same fields as a [bulk lookup](#bulk-lookup) `sources` entry: `source_id`, `name`, `license`, `redistributable`, `commercial_use` (`null` when unknown), tenant-adjusted `reliability`, `first_seen`, `last_seen`, `retrieved_at` and `source_url`. Entries are sorted by `source_id`. Existing fields are unchanged; on `GET /v1/entities/:id`, `sources` and `source_assertions` keep returning the raw provenance records.

- List entries cover the source records of the entity itself. Detail responses also cover the source of every returned relationship, and `GET /v1/entities/:id` covers all visible members of the canonical identity group. Related entities embedded in relationships are not included; fetch them by ID for their own licences.
- `redistributable` is true only when the source's licence record allows redistribution and every contributing record was marked redistributable. `commercial_use` comes from the source's [licence record](intelligence-sources.md#licence-records).
- `first_seen` and `last_seen` are the earliest and latest dates the source gives: publication dates for entity records and first/last sightings for relationships, `null` when it gives none. `retrieved_at` is the newest retrieval and `source_url` comes from the newest record that has one.
- Sources excluded by the tenant's source policy never appear, and their relationships are already left out. Tenant-private `upload` and `customer` records are not listed.

Licence data is read in a fixed number of D1 statements per response and aggregated per entity and source in SQL, so the response size does not grow with the number of records a source delivered.
