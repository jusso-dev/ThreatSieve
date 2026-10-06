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
| `GET /v1/me`                                                                                      | authenticated        |
| `GET /health`, `GET /ready`                                                                       | public, minimal data |

Bulk JSON takes `{ "observables": ["example.com", {"observable":"192.0.2.5","type":"ipv4"}] }`. Uploads take a raw UTF-8 body and explicit format. CSV needs `observable` (or `indicator`) and optional `type` headers. A 202 response includes the tenant-scoped job ID. Poll `/v1/jobs/:id`; stages report ingestion and classification separately. `pipeline_status` is `running`, `complete`, or `failed` across all child pages and stages; stop polling on a terminal value. `totals` counts processed and rejected inputs. Limits are 16 MiB and 100,000 items per upload.

Bulk endpoints accept an optional `Idempotency-Key` (1–200 characters). Reuse it when retrying the same parsed inputs: concurrent requests converge on one tenant-scoped job and one audit record. A different body under the same key returns 409 `IDEMPOTENCY_CONFLICT`. Reservations persist until operator cleanup; they do not expire automatically.

Feedback requires `{ "reason": "Validated against source evidence", "field": "assessment" }`. Include `expected_revision` from the assessment (`0` when absent) to protect against stale edits. The UI always supplies it; a stale or concurrent conflicting edit returns 409 `ASSESSMENT_CHANGED`. Reload the assessment before retrying. Modify can include a structured `value`; original model values remain available and the analyst overlay is stored separately. Feedback invalidates classification cache entries, creates an audit event, increments the revision and queues a revised STIX export in one transaction. Confirmed decisions leave the review queue; rejected, modified and needs-investigation decisions remain until resolved. Tenant relationship rejection removes the edge from subsequent graph/candidate retrieval for that tenant and invalidates its classification cache.

Assessments retain `schema_version`, observable, maliciousness probability/classification, role, confidence factors, ATT&CK mappings, potential actor associations, structured customer relevance, recommendations, evidence, provenance and full runs. `demo: true` labels synthetic records. Do not interpret `actors` as verified attribution or automatically execute `recommended_actions`.

Errors use `{ "error": { "code", "message", "request_id" } }`. Validation errors can also include field issues. Common codes: UNAUTHORIZED, FORBIDDEN, NOT_FOUND, VALIDATION_ERROR, INVALID_OBSERVABLE, RATE_LIMITED, AI_BUDGET_EXHAUSTED, FEED_DISABLED.

Entity lists default to 50 and cap at 100 records. Graph depth caps at three, nodes at 100 and edges at 200. The graph response indicates truncation. Intelligence search does exact canonical/alias lookup plus bounded prefix search; it is not a semantic answer generator.

## Operational recovery

`GET /v1/feeds/:id/jobs` lists outstanding global feed jobs. `POST /v1/feeds/:id/jobs/:jobId/replay` requires `feeds:write` and requeues only failed jobs belonging to that feed. Tenant bulk jobs use `/v1/jobs/:id/replay` with tenant-scoped `admin`. Poison messages with invalid job schemas are quarantined in R2.

`GET /v1/entities/:id` returns a visible entity, all retained source provenance, and bounded visible relationships. Actors include a source-weighted fingerprint. Assessment pagination uses opaque composite cursors to preserve records with equal creation timestamps.

`GET /v1/assessments` accepts `view=all|attention|review`, `q`, `limit` and `cursor`. Filtering is performed before pagination. Responses include tenant-wide `summary` counts and the top three attention items in `priority`; those counts do not depend on the current page. Invalid cursors return 400 `INVALID_CURSOR`.

Better Auth browser routes include sign-in, sign-up, sign-out, email verification, password reset and the organization plugin’s invitation/member endpoints. API Worker routes use `/auth/*`; the web proxy exposes `/api/auth/*`. Organization creation/deletion are disabled. The legacy `/v1/session` key exchange is development-only; production sign-out uses `POST /api/auth/sign-out`.

## Analyst library and saved triage views

`GET /v1/entities` requires `intel:read`. Parameters: `q` (literal name/alias/external-ID prefix, max 256 characters), `type` (entity type), `source` (source ID), `limit` (1–100, default 50), `cursor` (opaque). Returns `{data, next_cursor}` ordered by case-insensitive name then ID. Visibility is applied before pagination. Existing `/v1/actors`, `/v1/malware`, `/v1/campaigns` and `/v1/attack/techniques` retain their ID-based cursor format and now consistently enforce visibility.

`GET /v1/assessments` also accepts `severity`, `classification`, `observable_type`, `status`, `min_confidence` (0–1), `observed` (`yes`/`no`) and `sort` (`newest`, `oldest`, `confidence`, `relevance`). Filters apply to the whole tenant dataset. Classification uses the analyst override when present. Use the returned opaque cursor unchanged; reset it when filters or sort change. Historical newest-first cursors remain supported. Summary counts are workspace-wide, independent of table filters.

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
