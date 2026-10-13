# Intelligence operations

ThreatSieve retains its Cloudflare collection and Clef decision pipeline. The enterprise workspace adds human analysis around the same entities and evidence. Assessment investigation URLs remain `/investigations/:assessmentId`; collaborative investigations use `/cases/:id`.

## Analyst workflow

1. Define an intelligence requirement with a question, owner, priority, stakeholders, collection criteria and review date.
2. Active requirements and watchlists scan existing visible intelligence through background jobs and process new intelligence changes. Structured countries, technologies, actors and ATT&CK identifiers match exactly, case-insensitively. Keywords search supplied text. Criteria are ANDed across dimensions, ORed within each dimension.
3. Review matching intelligence and its original evidence. A match is a collection suggestion. Linking supporting evidence or an assessment is an analyst action, not automatic confirmation that the question has been answered.
4. Open a canonical dossier to distinguish threat score, confidence, organisational relevance and priority. Inspect each contributing factor and the missing evidence.
5. Pin entities into a collaborative investigation. Record a hypothesis, tasks, notes and decisions. All edits require the current revision; conflicting edits return 409 instead of overwriting another analyst.
6. Assemble a collection or author a report using references to original records. Export JSON, CSV, STIX, MISP event JSON or printable HTML. Publish an eligible collection as a tenant-authenticated TAXII snapshot.

Sightings are observations, not threat verdicts. They preserve source event IDs, UTC timestamps, asset, environment, count, confidence and context. Replaying the same event is idempotent; conflicting content with the same source event ID returns 409. Sightings remain tenant-private and never automatically become source-confirmed malicious indicators.

## Intelligence requirements

Coverage is the percentage of configured criteria dimensions supported by linked, qualifying evidence. It is **not** a percentage answer-completeness score. Supporting evidence must satisfy the minimum confidence and date range. Contradictory references do not increase coverage. Freshness is the newest supporting observation. Confidence averages evidence confidence weighted by the workspace's source reliability policy. New evidence counts records created since the last review. Undefined criteria, absent support, uncovered dimensions, stale support and analyst-authored gaps are explicit.

Coverage is materialized for the dashboard, refreshed on edits and intelligence processing, and cached for five minutes on detail retrieval. In-flight background matches can lag collection. Review the timestamp and refresh a record when investigating a fresh source change.

## Ownership and visibility

All operational objects, links, sightings, matches, notifications, source ratings, metrics and execution histories carry `tenant_id`. Object references and owners/collaborators/stakeholders/task assignees are checked against tenant visibility and membership. Private collections are readable by their owner, collaborators and tenant administrators. Other workspace objects are shared within the tenant. Viewers cannot mutate analyst records. Only administrators configure playbooks and source policy. Notification read state is personal.

Global public intelligence is shared; telemetry and investigations are not. No cross-tenant event is dispatched for a private sighting. Global changes may independently match each tenant's criteria, without revealing other tenants' identities or private evidence. The existing anonymized correlation policy remains unchanged.

## Dossiers, graph and history

The `IntelligenceCard` dossier separates overview, relationships, evidence, sightings, timeline, ATT&CK, investigations and history. Model mappings remain labelled and traceable to evidence. Unknown actor association is valid.

Graph requests default to two hops and allow one to three. Confidence, source, relationship, neighbour type and date filters apply before per-node limits. Graphs stop at 100 nodes, 200 edges and 30 relationships per expanded node and disclose truncation. Expansion pivots to a new bounded neighbourhood. Collapse hides a branch while preserving nodes reachable through other visible paths. Shortest connection paths are undirected paths within the loaded, authorized graph—not claims about the whole intelligence graph. Blue borders identify tenant sightings. Nodes can be pinned into workspace objects.

History includes source evidence, relationships, assessments, changes and analyst decisions. Time windows are 24 hours, 7/30/90 days, one year or all retained events, with bounded results and truncation disclosure. Relationship assertions retain source-specific versions in `relationship_assertions`; the current relationship is not the only historical record.

## Source quality and context

Source operations show sync history, accepted additions, repeated/updated records, rejected records, fetch/queue latency, failures, replay, samples and licensing. Admiralty A–F reliability and 1–6 information credibility are analyst assessments. The false-positive fraction is computed only from tenant-reviewed malicious assessments mentioning the source; it is not a population-wide estimate or proof of the source's accuracy.

Excluding a source changes future assessments and current dossiers in that tenant. Shared feed ingestion continues, and previous assessments retain their original evidence. Source ratings affect versioned confidence inputs and therefore classification cache keys.

Environment profiles include technologies, vendors, products, platforms, operating systems, industries, countries, regions, brands, domains, subsidiaries, critical assets, software, identity providers, security products, VIPs and exposed services. Relevance uses exact structured source/observation matches. Geographic proximity, brand impersonation or exposure are never inferred merely from a string resemblance.

## Operational limits

Objects contain at most 100 explicit references and 100 investigation tasks. Matching is paginated and asynchronous. Collection package exports allow at most 100 matched entities plus explicit references; narrow a large filtered collection into purpose-specific packages. Nested workspace exports are bounded to 20 objects and detect cycles. This protects interactive export requests from unbounded graph traversal. TAXII distributes the resulting snapshot with pagination.

There is no autonomous containment, arbitrary URL inspection, generated attribution or uncited AI report writing. Reports are analyst-authored. Live integration acceptance, feed contracts, source/model calibration, retention policy and workload load testing remain deployment responsibilities.

## Downstream handoff

ThreatSieve stays the intelligence-decision system: it collects evidence, scores and ranks assessments, records analyst judgment, and publishes eligible intelligence. Case ownership, remediation work, SLAs and outcome feedback belong to OpenCTI, SIEM or ITSM systems that receive the published package or alert.

Handoffs need a visible state and an acknowledgement. A publication or alert that leaves ThreatSieve without a recorded handoff state, and without an acknowledgement from the receiving system or operator, is incomplete for operational use. Design the handoff so analysts can see: what was sent, to which system, in which state (queued, delivered, acknowledged, rejected), and when the acknowledgement arrived.

This branch still exposes `/cases`, `/automations` and `/sightings` and their APIs. Those surfaces support local collaborative investigation, playbook configuration and tenant-private observations. They are not a substitute for downstream case ownership in OpenCTI/SIEM/ITSM. Product design for handoffs should keep those local surfaces and add explicit handoff + acknowledgement states on publication and alert paths — do not treat the local UI as removed.

### Production workflow chain

Map the operator path to concrete surfaces. Gaps closed by the 2026-10-13 remediation are marked closed; remaining gaps stay open.

1. **Requirements** — `/requirements` and `/v1/requirements`. Criterion keys render through the `criterionLabel` map; searchable source/entity pickers and a plain-language preview state what will match. Closed: label/preview ergonomics (`apps/web/components/workspace-objects.tsx`, `tests/reports.test.ts`). Open: live customer acceptance of requirement-driven collection.
2. **Collection** — feed sync, bulk upload and workspace matching. Bulk results return `{processed, accepted, duplicates, rejected, errors}`; matches expose `match_status` and `last_evaluated_at`. Closed: diagnostics (`workers/ingest/upload.ts`, `migrations/0024_matching_state.sql`, `tests/bulk-diagnostics.test.ts`). Open: ThreatFox/URLhaus secrets and feed licensing.
3. **Canonical evidence** — dossier, library and assessment list. Latest assessment per observable by default; `canonical_aliases` (migration 0025) records reversible aliases; mirrors that share a `sourceRecordId` do not count as independent corroboration in the canonical module. Closed: identity collapse (`packages/database/src/canonical.ts`, `tests/canonical.test.ts`). Open: `packages/scoring` still keys multi-source factors on `source.independent_group`.
4. **Relevance** — environment profile and exposure scoring. Empty profile → applicability unknown, relevance null; KEV titles as "Known exploited vulnerability", never "your exposed asset". Queue `sort=relevance` orders by operational urgency (UI: "Highest operational urgency"); zero-evidence items go to an enrichment backlog. Closed: exposure honesty and urgency ranking (`packages/enterprise/src/scoring.ts`, `packages/enterprise/src/urgency.ts`, `tests/exposure.test.ts`). Open: customer-owned inventory population.
5. **Analyst judgment** — investigation and decision endpoints. One effective decision; overrides with `field != "assessment"` return 422 `INVALID_OVERRIDE`. Closed: decision state (`packages/database/src/decision-state.ts`, `tests/analyst-state.test.ts`).
6. **Controlled publication** — STIX/TAXII/MISP/HTML exports and report publish. The controlled publication path drops derived claims when evidence is restricted; report claims carry citations; `publishedRevisions` freeze on publish. Closed: publication policy and report immutability (`packages/stix/src/policy.ts`, `tests/publication-policy.test.ts`, `tests/reports.test.ts`). Freshness/expiry and cluster observation times feed eligibility (`packages/intel/src/freshness.ts`, `migrations/0026_cluster_observation.sql`).
7. **Downstream action** — handoff into OpenCTI, SIEM or ITSM for case ownership, containment and SLA clocks. A downstream action happens in the receiving system; ThreatSieve records what was published. Open: visible handoff state + acknowledgement wiring on the publication/alert path; customer integration acceptance.
8. **Outcome feedback** — return of close/false-positive/missed-detection signals into source ratings and analyst feedback. Sightings and `analyst_feedback` already exist as local inputs; closed-loop outcome feedback from the downstream case system is not yet a productised handoff. Open: acknowledgement and outcome-feedback contract with the chosen ITSM/SIEM/OpenCTI consumer.
