# API v1

Authenticate with `Authorization: Bearer $THREATSIEVE_API_KEY`, or exchange a scoped key at `POST /v1/session` for an eight-hour HttpOnly session. Sessions preserve the originating key's scopes and expire/revoke with that key. Session mutations require the configured web Origin.

```sh
curl -X POST http://127.0.0.1:8787/v1/assess \
  -H "Authorization: Bearer $THREATSIEVE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"observable":"example.com"}'
```

`POST /v1/assess` returns a versioned assessment synchronously. Optional `type` overrides safe type detection. An unrecognised or ambiguous value returns 422. Provider/classifier failure is an error, never a fabricated assessment.

| Routes                                                                                             | Scope                |
| -------------------------------------------------------------------------------------------------- | -------------------- |
| `POST /v1/assess`, `POST /v1/assess/bulk`, `POST /v1/uploads?format=text                           | csv                  | json             | stix`       | assessment:write |
| `GET /v1/assessments`, `GET /v1/assessments/:id`                                                   | assessment:read      |
| `POST /v1/assessments/:id/confirm                                                                  | reject               | modify           | investigate | reclassify`      | assessment:write |
| `GET /v1/assessments/:id/stix`                                                                     | assessment:read      |
| `GET /v1/observables/:id`                                                                          | intel:read           |
| `GET /v1/actors`, `/v1/malware`, `/v1/campaigns`, `/v1/attack/techniques` and `/:id` detail routes | intel:read           |
| `GET /v1/search?q=`, `GET /v1/graph/:id?depth=1..3`                                                | intel:read           |
| `GET /v1/clusters`, `GET /v1/clusters/:id`                                                         | intel:read           |
| `GET /v1/feeds`, `GET /v1/feeds/:id/health`                                                        | feeds:read           |
| `POST /v1/feeds/:id/sync`                                                                          | feeds:write          |
| `POST /v1/relationships/:id/confirm                                                                | reject`              | assessment:write |
| `GET /v1/jobs/:id`, `GET /v1/exports`, `GET /v1/exports/:id`                                       | assessment:read      |
| `POST /v1/jobs/:id/replay`                                                                         | admin                |
| `GET /v1/environment`                                                                              | intel:read           |
| `PUT /v1/environment`                                                                              | admin                |
| `POST /v1/observations`                                                                            | assessment:write     |
| `POST /v1/api-keys`, `DELETE /v1/api-keys/:id`, `GET /v1/ops`                                      | admin                |
| `GET /v1/me`, `DELETE /v1/session`                                                                 | authenticated        |
| `GET /health`, `GET /ready`                                                                        | public, minimal data |

Bulk JSON takes `{ "observables": ["example.com", {"observable":"192.0.2.5","type":"ipv4"}] }`. Uploads take a raw UTF-8 body and explicit format. CSV needs `observable` (or `indicator`) and optional `type` headers. A 202 response includes the tenant-scoped job ID. Poll `/v1/jobs/:id`; stages report ingestion and classification separately. Limits are 16 MiB and 100,000 items per upload.

Feedback requires `{ "reason": "Validated against source evidence", "field": "assessment" }`. Modify can include a structured `value`; original model values remain available and the analyst overlay is stored separately. Feedback invalidates classification cache entries and creates an audit event.

Assessments retain `schema_version`, observable, maliciousness probability/classification, role, confidence factors, ATT&CK mappings, potential actor associations, structured customer relevance, recommendations, evidence, provenance and full runs. `demo: true` labels synthetic records. Do not interpret `actors` as verified attribution or automatically execute `recommended_actions`.

Errors use `{ "error": { "code", "message", "request_id" } }`. Validation errors can also include field issues. Common codes: UNAUTHORIZED, FORBIDDEN, NOT_FOUND, VALIDATION_ERROR, INVALID_OBSERVABLE, RATE_LIMITED, AI_BUDGET_EXHAUSTED, FEED_DISABLED.

Entity lists default to 50 and cap at 100 records. Graph depth caps at three, nodes at 100 and edges at 200. The graph response indicates truncation. Intelligence search does exact canonical/alias lookup plus bounded prefix search; it is not a semantic answer generator.

## Operational recovery

`GET /v1/feeds/:id/jobs` lists outstanding global feed jobs. `POST /v1/feeds/:id/jobs/:jobId/replay` requires `feeds:write` and requeues only failed jobs belonging to that feed. Tenant bulk jobs use `/v1/jobs/:id/replay` with tenant-scoped `admin`. Poison messages with invalid job schemas are quarantined in R2.

`GET /v1/entities/:id` returns a visible entity, all retained source provenance, and bounded visible relationships. Actors include a source-weighted fingerprint. Assessment pagination uses opaque composite cursors to preserve records with equal creation timestamps.
