# Plan: ThreatSieve audit remediation — findings 1–11 end to end

Depth: tree 4 (root → 4 branches → 11 leaves)   Mode: orchestrated
Budget note: a competent single pass would be several working days; 11 leaves, each 20–60 min of focused work.

Source: analyst audit report (session of 2026-10-13), 11 findings (P1×7, P2×4).
Recommended order from the audit is preserved: export eligibility + expiry →
timestamps + analyst state → canonical identity + asset relevance → workflow UX
→ production acceptance.

Baseline before fan-out (2026-10-13 15:10): `pnpm test` → 12 files / 113 tests
passed; `pnpm typecheck` clean. Working tree has pre-existing uncommitted
changes (feed/ops work, `migrations/0021_outbox_dispatch_token.sql`); every leaf
must preserve them and may not revert files it does not own.

## Contract

Decided BEFORE fan-out. Everything a leaf could get wrong about its neighbors.

### Scope boundary

- In scope: code, schema, tests, and docs inside this repo.
- Out of scope (ops actions outside the repo — leaf 1.4.3 records them as open
  items with owners, they get ABANDON lines, never silent drops): ThreatFox/
  URLhaus Worker secrets + feed licensing, production MFA policy enforcement in
  the IdP, SSO IdP configuration, alert destination approval + delivery test,
  contractual RPO/RTO + retention, sustained load testing, customer integration
  acceptance.
- Audit note discrepancy: the report says the local branch "deliberately removes
  case/automation/sighting UI", but `/cases`, `/automations`, `/sightings` and
  their APIs are present on this branch (shell.tsx:45,49,50; enterprise.ts
  routes). Leaf 1.4.3 records the handoff design requirement (OpenCTI/SIEM/ITSM
  ownership + SLA handoffs with acknowledgements) as product-design work in
  docs, and does not remove any UI.

### Global naming and conventions

- New pure logic goes in `packages/*` modules, exported functions camelCase,
  types PascalCase, string-literal union codes SCREAMING_SNAKE.
- Machine codes (reasons, states) are SCREAMING_SNAKE string unions; UI maps
  them to readable labels — never render raw camelCase/Snake keys (finding 10).
- All timestamps ISO-8601 strings. Vocabulary (finding 3): `observedAt` = when
  the thing was true in the world; `retrievedAt` = when a source reported it to
  us; `processedAt` = when our pipeline wrote it. Never write processing time
  into an observation field.
- Additive schema changes only; a leaf adding fields to shared schema files
  wraps them in a `// <leaf-id> additive` comment block and touches nothing else
  in the file. Dispatch is strictly sequential so shared files are edited one
  leaf at a time.
- DDL: each leaf has a reserved migration number (below). Unused numbers stay
  unused. Migrations are idempotent-safe SQLite/D1 (`ALTER TABLE ... ADD COLUMN`
  / `CREATE TABLE IF NOT EXISTS`), matching existing style in `migrations/`.
- Tests: each leaf owns one new vitest file (named below) and may update the
  existing test files listed in its gates when its behavior change breaks them.
  New tests are placed in `tests/` root (vitest include `tests/**/*.test.ts`).

### Shared interfaces (pinned names — neighbors rely on these exact names)

1. **Publication policy** (leaf 1.1.1), module `packages/stix/src/policy.ts`:
   - `type PublicationAudience = "research" | "operational"`
   - `interface PublicationState { audience; eligible: boolean; reasons: string[]; valid_until: string | null; revoked: boolean; last_observed: string | null; activity: "active" | "stale" | "expired" | "unknown" }`
   - `function publicationState(a: Assessment, now?: string): PublicationState`
   - `exportStix(a, options: { includeRestricted?: boolean; audience: PublicationAudience }): StixBundle`
     (existing callers pass `audience: "research"` to keep today's behavior).
   - Operational exports mark non-eligible indicators non-actionable:
     `x_threatsieve_publication_state`, `x_threatsieve_approved_for_operational_use: false`,
     `valid_until`, `revoked` (STIX 2.1 fields where applicable), and never emit
     `indicator_types: ["malicious-activity"]` for non-eligible indicators.
   - Eligibility (operational) requires ALL of: analyst-confirmed or
     auto-accepted review state (`status != "pending"` semantics per
     `human_review`), at least one permitted (redistributable) evidence record,
     non-stale evidence (leaf 1.1.2 freshness), and confidence ≥ 0.5.
   - Derived-data rights: derived classification/role/attack/malware claims are
     emitted only from permitted evidence; when the only supporting evidence is
     restricted, the derived claim is dropped too (audit case: C2 role survived
     evidence stripping — that is the bug).
2. **Freshness** (leaf 1.1.2), module `packages/intel/src/freshness.ts`:
   - `interface FreshnessState { first_observed: string | null; last_observed: string | null; valid_until: string | null; activity: "active" | "stale" | "expired" | "unknown"; stale: boolean; stale_reasons: string[] }`
   - `function freshness(evidence: { observedAt?: string; data?: Record<string, unknown> }[], now?: string): FreshnessState`
   - Policy defaults: `stale` when newest evidence `observedAt` > 30 days old;
     `expired` > 90 days; `unknown` when no evidence dates. Evidence whose
     source status was offline at collection (e.g. Feodo `status: "offline"`)
     can never yield `activity: "active"`.
   - FreshnessState fields are what leaf 1.1.1 reads for `valid_until`/`activity`.
   - Recommended actions (packages/clef): `block` requires fresh evidence
     (≤ 14 days) AND not `human_review`; otherwise the action is downgraded to
     `monitor`/`hunt` with reason code `FRESH_EVIDENCE_REQUIRED`. Existing
     reason code `STALE_INTELLIGENCE` is reused where it already applies; new
     codes are added to `reasonCodes` in packages/schemas: `FRESH_EVIDENCE_REQUIRED`,
     `EXPIRED_INDICATOR`, `HISTORICAL_ASSOCIATION_ONLY`.
3. **Clusters** (leaf 1.1.3), migration `0022_cluster_observation.sql`:
   `threat_clusters` gains `first_observed`, `last_observed`, `last_processed_at`,
   `grouping_key`, `rationale`. `threat_clusters.last_seen` keeps its name but
   becomes max evidence `observedAt` (observation semantics). Correlate writes
   `last_processed_at = now` and recomputes confidence/rationale on every run
   (no first-writer-wins freeze). Rationale string format:
   `"<grouping kind> <key>; N evidence records from M sources"` where grouping
   kind ∈ `shared-malware|shared-report|shared-certificate`. `/v1/clusters` and
   the clusters page surface rationale, observed vs processed times, and the
   note that shared association is not coordinated activity.
4. **Effective decision** (leaf 1.2.1), module `packages/database/src/decision-state.ts`:
   - `function effectiveDecision(a: Assessment): { classification; role: ThreatRole | null; source: "analyst" | "model"; decidedAt: string | null }`
   - `function effectiveRecommendations(a: Assessment)` — one decision drives
     recommended actions, queue placement, publication eligibility and UI
     wording. Model output is retained as history (`x_threatsieve_model_classification`
     already exists; nothing overwrites `a.malicious`).
   - UI wording contract: an analyst decision renders as "Analyst confirmed …";
     the phrase "confidence gates passed" (and equivalents) is reserved for
     automatic gates and must never be shown for analyst-decided assessments.
     Reproduction case from the audit (benign override → confirm → page still
     recommends INVESTIGATE and claims gates passed at 0% confidence) becomes a
     regression test.
5. **Operational urgency** (leaf 1.2.2), module `packages/enterprise/src/urgency.ts`:
   - `function operationalUrgency(a: Assessment, ctx?: { kev?: boolean; exposedAssets?: number }): { urgency: number; components: { assetImpact; exposure; freshness; exploitation; evidenceConfidence; reviewState } }` (0–1 each, weighted sum 0–1).
   - Priority queue ranks by `urgency` (not `customer.relevance`). Insufficient
     evidence (zero evidence records) routes to an **enrichment backlog** —
     excluded from the priority queue, surfaced as its own section. Badges are
     four distinct labelled values: threat severity / evidence confidence /
     customer relevance / operational urgency. A `high` threat badge no longer
     shares a row with an unexplained `low` relevance badge — each is labelled.
6. **Score semantics** (leaf 1.2.3): factor code `MULTI_SOURCE_CONFIRMATION`
   (packages/scoring/src/index.ts) is emitted only when ≥2 independent source
   groups support the assessment; single-source gets `SINGLE_SOURCE_SUPPORT`
   (new code in packages/schemas `ConfidenceFactor.code` union). Heuristic
   dossier scores are labelled `/100 heuristic` in UI copy; "Evidence strength"
   label becomes "Overall confidence". `docs/confidence-model.md` gains a
   definitions table (malicious probability / confidence / evidence strength /
   relevance / urgency) and the evaluation section states the dataset is
   synthetic, small, and uncalibrated.
7. **Canonical identity** (leaf 1.3.1), module `packages/database/src/canonical.ts`,
   migration `0025_canonical_aliases.sql` (`entity_aliases(tenant_id, canonical_id, alias_id, basis, created_at)` — reversible):
   - `function canonicalEntities(...)` / `function latestAssessmentPerObservable(...)`.
   - Default assessment views show the latest assessment per observable with
     `assessment_count` and expandable history; source assertions stay
     underneath (lineage preserved); mirrored sources never count as
     independent corroboration (explicit `mirrored: true` when sources share an
     upstream `sourceRecordId`/report id).
8. **Customer exposure** (leaf 1.3.2): `EnvironmentSchema` gains
   `assets: { id, name, product, version?, vendor?, criticality: "critical"|"high"|"medium"|"low", internetExposed?: boolean, owner?, inventoryFreshness?: string, lastSeenAt? }[]`.
   Wording contract: "known exploited vulnerability" (KEV, from `vulnerabilities.kev`)
   is never presented as "your exposed asset". With an empty profile the card
   reads "Applicability to your environment unknown" — never a 0% exposure
   claim. The hardcoded CVE card title "Exploited vulnerability exposure"
   (operations.tsx:363) is replaced by the wording contract.
9. **Bulk/matching diagnostics** (leaf 1.4.1), migration `0024_matching_state.sql`:
   `workspace_matches` gains `match_status ('queued'|'running'|'complete'|'failed')`
   and `last_evaluated_at`. Bulk result shape
   `{ processed, accepted, duplicates, rejected, errors: [{ index, error }] }`
   is returned in full by `GET /v1/jobs/:id`; the bulk page renders line-level
   errors, counts, result links and retry. Matching UI shows state +
   last-evaluated instead of a bare "No matches yet".
10. **Requirements/reports** (leaf 1.4.2): criterion keys get a label map
    (`sourceIds`→"Sources", `entityTypes`→"Entity types", `keywords`→"Keywords",
    `technologies`→"Technologies", `industries`→"Industries", `countries`→"Countries",
    `actors`→"Threat actors", `techniques`→"ATT&CK techniques", `tags`→"Tags",
    `minConfidence`→"Minimum confidence", `from`/`to`→"Observed between"),
    searchable source/entity pickers, and a plain-language criterion preview.
    Reports gain `claims: { text, sourceRefs: string[] }[]` rendered with
    claim-level citations, `tlp: "clear"|"green"|"amber"|"amber+strict"|"red"`,
    `audience: string[]`, reviewer approval (`approvedBy`/`approvedAt`), and
    immutable published revisions (publish writes a frozen revision; further
    edits create a new revision).
11. **Readiness** (leaf 1.4.3): `docs/readiness.md` register gains rows/evidence
    for this remediation plus an explicit open-ops list (see scope boundary),
    and `docs/intelligence-operations.md` gains the downstream-handoff design
    section (case ownership, remediation, SLAs belong to OpenCTI/SIEM/ITSM with
    visible handoffs + acknowledgements).

### File ownership (no two leaves edit the same file concurrently; dispatch is strictly sequential)

| Leaf | Owns (edit) | Reserved migration | New test file |
|---|---|---|---|
| 1.1.1 | packages/stix/src/{index,policy}.ts, workers/export/index.ts, apps/api/src/index.ts (export/stix routes only), tests/decisions.test.ts, tests/integration.test.ts (export assertions) | 0023_publication_state.sql (optional) | tests/publication-policy.test.ts |
| 1.1.2 | packages/intel/src/freshness.ts (new), packages/clef/src/index.ts, packages/schemas/src/index.ts (additive: reason codes), apps/web/components/{investigation,intelligence-card}.tsx (freshness UI) | — | tests/freshness.test.ts |
| 1.1.3 | workers/correlate/index.ts, migrations/0022_cluster_observation.sql, apps/api/src/index.ts (cluster routes), apps/web/app/clusters/page.tsx | 0022 | tests/correlate.test.ts |
| 1.2.1 | packages/database/src/{decision-state.ts (new), repository.ts, assessment-query.ts}, apps/web/components/investigation.tsx (wording), tests/decisions.test.ts | — | tests/analyst-state.test.ts |
| 1.2.2 | packages/enterprise/src/urgency.ts (new), packages/enterprise/src/scoring.ts, packages/database/src/{repository.ts, assessment-query.ts}, apps/web/components/operations.tsx | — | tests/priority-queue.test.ts |
| 1.2.3 | packages/scoring/src/index.ts, packages/schemas/src/index.ts (additive: factor codes), apps/web/components/{investigation,intelligence-card}.tsx (labels), docs/confidence-model.md | — | tests/scoring-labels.test.ts |
| 1.3.1 | packages/database/src/canonical.ts (new), migrations/0025_canonical_aliases.sql, apps/api/src/index.ts (search/list routes), apps/web/components/{intelligence-library,intelligence-detail}.tsx | 0025 | tests/canonical.test.ts |
| 1.3.2 | packages/schemas/src/index.ts (additive: EnvironmentSchema.assets), apps/api/src/index.ts (environment route), apps/web/app/inventory/page.tsx, apps/web/components/operations.tsx, packages/enterprise/src/scoring.ts | 0026_environment_assets.sql (optional) | tests/exposure.test.ts |
| 1.4.1 | workers/ingest/upload.ts, apps/api/src/index.ts (jobs routes), apps/web/app/bulk/page.tsx, apps/web/components/workspace-activity.tsx, packages/enterprise/src/{automation,intelligence}.ts, migrations/0024_matching_state.sql | 0024 | tests/bulk-diagnostics.test.ts |
| 1.4.2 | apps/web/components/workspace-objects.tsx, packages/enterprise/src/{export,repository}.ts, packages/schemas/src/enterprise.ts (additive) | 0027_workspace_revision.sql (optional) | tests/reports.test.ts |
| 1.4.3 | docs/readiness.md, docs/intelligence-operations.md | — | — (manual gates) |

Files listed under two leaves (apps/api/src/index.ts, packages/database/src/repository.ts,
apps/web/components/*, packages/schemas, packages/enterprise/src/scoring.ts) are
**region-serialized**: each leaf edits only the routes/sections its gates name,
never reformatting, never touching a sibling leaf's region. Sequential dispatch
makes this safe; if a leaf needs a sibling's region, it must say so in the
status log instead of editing it.

### Error and behavior conventions

- API errors keep the existing `AppError`/`{ error: { code, message } }` style.
- Every new user-visible state has an explicit "unknown" presentation; never
  fabricate 0% or "fresh" for missing data (findings 2, 7).
- Audit trail: every behavioral change keeps the existing audit_events and
  analyst_feedback trails intact (findings praise provenance/history — keep it).

## Tree

- 1 ThreatSieve audit remediation (findings 1–11) ....... gates/root.md
  - 1.1 Publication & freshness (findings 1, 2, 3) ...... gates/node-1.1.md
    - 1.1.1 Publication policy & STIX export gating (F1, P1) .. gates/leaf-1.1.1.md
    - 1.1.2 Indicator expiry, activity & stale warnings (F2, P1) .. gates/leaf-1.1.2.md
    - 1.1.3 Cluster observation timestamps & rationale (F3, P1) .. gates/leaf-1.1.3.md
  - 1.2 Decision & ranking semantics (findings 4, 5, 8) .. gates/node-1.2.md
    - 1.2.1 One effective analyst decision (F4, P1) ...... gates/leaf-1.2.1.md
    - 1.2.2 Priority queue decomposition & enrichment backlog (F5, P1) .. gates/leaf-1.2.2.md
    - 1.2.3 Score definitions & factor naming (F8, P1) .... gates/leaf-1.2.3.md
  - 1.3 Identity & exposure (findings 6, 7) .............. gates/node-1.3.md
    - 1.3.1 Canonical entities & source assertions (F6, P2) .. gates/leaf-1.3.1.md
    - 1.3.2 Customer exposure correctness (F7, P1) ....... gates/leaf-1.3.2.md
  - 1.4 Workflow UX & production acceptance (findings 9, 10, 11) .. gates/node-1.4.md
    - 1.4.1 Bulk/job diagnostics & matching state (F9, P2) .. gates/leaf-1.4.1.md
    - 1.4.2 Requirements & reports ergonomics (F10, P2) ... gates/leaf-1.4.2.md
    - 1.4.3 Production readiness register & handoffs (F11, P1) .. gates/leaf-1.4.3.md

## Status log

Append-only. One line per event.

- 2026-10-13 15:10 baseline: `pnpm test` 12 files / 113 tests passed; `pnpm typecheck` clean; pre-existing uncommitted changes noted and preserved.
- 2026-10-13 plan written, contract fixed.
- 2026-10-13 15:55 leaf 1.1.1 verified by parent (gate-check ALL MET 7/7; vitest publication-policy+decisions+integration = 47 passed; typecheck OK; audit regression asserted at tests/publication-policy.test.ts:234). Caller one-liners in packages/enterprise/src/export.ts:187, scripts/seed.ts:14. G4 gate wording aligned with contract (no hard-fail; non-actionable marking).
- 2026-10-13 16:22 leaf 1.1.2 verified by parent (gate-check ALL MET 7/7; vitest freshness+publication-policy = 30 passed; typecheck OK; Feodo-offline regression at tests/freshness.test.ts:200,285). Mechanical policy.ts integration onto shared freshness(); stable names for downstream: freshness(), FreshnessState, reassessmentTrigger(), freshEvidenceGate(), FRESH_EVIDENCE_DAYS.
- 2026-10-13 16:57 leaf 1.1.3 verified by parent (gate-check ALL MET 7/7; vitest correlate = 9 passed; db:validate OK; typecheck OK). Migration 0022 with FK-safe rebuild + SQL backfill; only wall clock is last_processed_at. Note: scripts/demo-data.ts seeds cluster last_seen with wall clock (demo-only, unowned) — flagged for a later pass.
- 2026-10-13 16:58 branch 1.1 integration gates ALL MET (6/6; full suite 15 files / 152 tests passed). Findings 1, 2, 3 closed pending root verification.
- 2026-10-13 17:55 leaf 1.2.1 verified by parent (gate-check ALL MET 6/6; vitest analyst-state+decisions = 20 passed; typecheck OK; audit sequence regression tests/analyst-state.test.ts:149, gates-claim false at :222). Behavior change: confirm/reject/investigate with field != "assessment" now 422 INVALID_OVERRIDE. Note: pre-existing uncommitted repository.ts hunks contain canonical/sourceStatements work — leaf 1.3.1 must build on them. Clef re-implements ≤14d gate in decision-state (web-safe); unify later if clef becomes web-importable.
- 2026-10-13 18:53 leaf 1.2.2 verified by parent (gate-check ALL MET 7/7; vitest priority-queue+analyst-state = 12 passed; typecheck OK; audit fixture .invalid-vs-KEV at tests/priority-queue.test.ts:162-240). Urgency computed in SQL (urgencySql) with TS parity asserted; 4-decimal rounding for SQLite/JS parity; unknown = neutral 0.5 + unknownComponents. Zero-evidence excluded from urgency surfaces only (attention unchanged). E2E label update in tests/system/analyst-workbench.e2e.ts:78. Docs follow-ups noted: docs/tip-ux-review.md, docs/api.md still describe relevance ordering (owner 1.4.3 sweep).
- 2026-10-13 19:35 leaf 1.2.3 verified by parent (gate-check ALL MET 6/6; vitest scoring-labels+decisions = 24 passed; typecheck OK; MULTI_SOURCE_CONFIRMATION gated to ≥2 groups at packages/scoring/src/index.ts:55-62,154-155). Factor renames: MULTI_SOURCE_CONFIRMATION→EVIDENCE_RELIABILITY (reliability term), LOW_EVIDENCE→EVIDENCE_STRENGTH/CLASSIFIER_DECISIVENESS, CUSTOMER_OBSERVED→DIRECT_EVIDENCE (confidence path), LOW_EVIDENCE→TRUNCATED_EVIDENCE; old→new map in docs/confidence-model.md. Dataset caveat auto-filled (SYNTHETIC_CHALLENGE_CAVEAT); strict runner refusal documented as outstanding. Follow-up flagged by leaf: operations.tsx composite-confidence label.
- 2026-10-13 19:38 driver integration edit: operations.tsx "Evidence confidence" → "Overall confidence" (header :212, card :430) to match finding-8 label semantics (composite a.confidence = "Overall confidence" everywhere).
- 2026-10-13 19:40 branch 1.2 integration gates ALL MET (5/5; full suite green at gate-check). Findings 4, 5, 8 closed pending root verification.
- 2026-10-13 19:40 WORK CUT HERE by user request — continuation instructions in resume.md. Not yet done: leaves 1.3.1, 1.3.2, 1.4.1, 1.4.2, 1.4.3; branch gates node-1.3, node-1.4; root gates (full suite, typecheck, lint, system e2e, playwright, finding→evidence map G8, uncommitted-preservation G9, report audit G10).
- 2026-10-13 20:06 leaf 1.3.1 verified by parent (gate-check ALL MET 6/6; vitest canonical.test.ts = 7 passed). Parent sent back twice: (1) assessment list ignored filters — now walks repo.assessments so view/q/sort/cursor/INVALID_CURSOR still apply, flat=1 keeps raw rows; (2) campaign collapse was attachSource-on-one-id — three putEntity rows sharing externalId/sourceRecordId now collapse at read time; (3) identity peers discovered globally then filtered with repo.visible so a private peer sharing externalId does not leak id or provenance (tests/canonical.test.ts tenant A/B case). Migration 0025 creates canonical_aliases, not a rebuild of 0001 entity_aliases. Scoring MULTI_SOURCE_CONFIRMATION still uses independent_group (unowned). GET /v1/assessments default is latest-per-observable with assessment_count.
- 2026-10-13 20:14 leaf 1.3.2 verified by parent (gate-check ALL MET 6/6; vitest exposure.test.ts = 6 passed, includes PUT/GET /v1/environment asset round-trip). Empty profile + KEV → applicability unknown, relevance null, title "Known exploited vulnerability"; old "Exploited vulnerability exposure" title removed. Asset product/version match, stale >90d caveat, SIEM/EDR sighting wording in evaluateCustomerExposure. No migration 0026 (assets in customer_environments JSON). Follow-up: unmatched asset profile returns relevance 0 (grounded negative); legacy technology strings do not by themselves produce an asset match.
- 2026-10-13 20:16 branch 1.3 integration gates ALL MET (5/5; gate-check ran full pnpm test ~73s and typecheck). Findings 6 and 7 closed pending root verification. Suite file/test counts were not in the captured tail — do not cite a number until re-measured.
- 2026-10-13 20:30 leaf 1.4.1 verified by parent (gate-check ALL MET 6/6; vitest bulk-diagnostics 3 + enterprise 21 passed after driver edit). processBulk cumulative shape processed/accepted/duplicates/rejected/errors; seenIds carried across pages. Migration 0024 adds match_status + last_evaluated_at; positional workspace_matches inserts replaced with named columns. Driver integration: GET /v1/workspace/:id/matches now returns match_status and last_evaluated_at (apps/api/src/enterprise.ts); workspace-activity labels those states instead of printing the raw key.
- 2026-10-13 20:39 leaf 1.4.2 verified by parent (gate-check ALL MET 6/6; vitest reports.test.ts = 3 passed). Criterion labels via criterionLabel; reportHtml cites sourceRefs inside each claim; publish snapshots publishedRevisions and later edits do not rewrite them. No migration 0027 (JSON on the workspace object).
- 2026-10-13 20:42 leaf 1.4.3 verified by parent (gate-check ALL MET 5/5). docs/readiness.md remediation rows + open-ops table; docs/intelligence-operations.md downstream handoff. ABANDON: G5-ThreatFox, G5-MFA, G5-SSO, G5-Alert, G5-RPO, G5-Load, G5-Customer. Scoring independent_group vs mirror flag remains open.
- 2026-10-13 20:45 branch 1.4 integration gates ALL MET (7/7 including bulk-pipeline + enterprise-workspace system e2e, full vitest, typecheck). Findings 9, 10, 11 closed pending root verification. Finding 11 closes as code-side done plus the seven ABANDON ops items.
- Finding→evidence map: F1 publication tests/publication-policy.test.ts (leaf 1.1.1). F2 freshness tests/freshness.test.ts (leaf 1.1.2). F3 clusters tests/correlate.test.ts + migrations/0022_cluster_observation.sql (leaf 1.1.3). F4 analyst decision tests/analyst-state.test.ts (leaf 1.2.1). F5 urgency tests/priority-queue.test.ts (leaf 1.2.2). F6 canonical tests/canonical.test.ts (leaf 1.3.1). F7 exposure tests/exposure.test.ts (leaf 1.3.2). F8 score labels tests/scoring-labels.test.ts (leaf 1.2.3). F9 bulk tests/bulk-diagnostics.test.ts (leaf 1.4.1). F10 reports tests/reports.test.ts (leaf 1.4.2). F11 docs/readiness.md + docs/intelligence-operations.md + gates/leaf-1.4.3.md ABANDON lines (leaf 1.4.3).
- 2026-10-13 21:10 CORRECTION: branch 1.4 line at 20:45 and root G6/G7 were false passes. gate-check EXPECT /pass|passed|ok/ matched failure tails. Measured e2e was 5 failed / 82 passed (.e2e/summary.md). Playwright exited 1 on tests/e2e/analyst.spec.ts:286. Lint failed on unused inDays in tests/publication-policy.test.ts. Root G3/G4/G5/G6/G7 unchecked until re-run. Fixes in progress: bulk e2e totals shape, browseCanonicalEntities cursor walk, extraAssessments as distinct observables, dossier overflow wrap, inDays removed.
- 2026-10-13 21:16 root gates re-measured green after the correction. G3 pnpm test 22 files / 194 tests (gate PASS, duration 94.49s). G4 typecheck OK. G5 lint OK. G6 full e2e 87 passed / 12 files (.e2e/summary.md). G7 Playwright 8 passed. Leaf boxes 69/69, branch boxes 23/23. Fixes: removed unused inDays; bulk e2e totals include accepted/duplicates; browseCanonicalEntities walks until the caller's limit and emits a real {id} cursor; extraAssessments are distinct observables so latest-per-observable still paginates; dossier/main min-width and overflow-wrap; analyst.spec.ts targets the Overall confidence table; scripts/dev-offline.ts applies pending D1 migrations before wrangler dev (local DB was stuck at 0018, so /v1/search 500ed on missing canonical_aliases). ABANDON unchanged: G5-ThreatFox, G5-MFA, G5-SSO, G5-Alert, G5-RPO, G5-Load, G5-Customer. Open: scoring MULTI_SOURCE_CONFIRMATION still keys off source.independent_group, not the mirror flag.
- 2026-10-13 22:00 release numbering: cluster observation SQL moved from migrations/0022_cluster_observation.sql to migrations/0026_cluster_observation.sql so it does not collide with origin/main migrations/0022_entity_source_record_lookup.sql. 0023 stays unused. 0026 is not an assets migration; customer environment assets remain JSON. Historical lines above still name the old filename.
