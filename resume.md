# RESUME — ThreatSieve audit remediation (findings 1–11)

Cut point: 2026-10-13 21:16. Root gates met. Do not redo leaves 1.1.1–1.4.3.

Re-measured at the close: `pnpm test` 22 files / 194 tests; `pnpm test:e2e` 87 passed / 12 files; Playwright 8 passed. Leaf boxes 69 checked, branch boxes 23 checked, root 10/10. ABANDON (not done): G5-ThreatFox, G5-MFA, G5-SSO, G5-Alert, G5-RPO, G5-Load, G5-Customer. Scoring still keys MULTI_SOURCE_CONFIRMATION off `source.independent_group`, not the mirror flag.

The 20:45 branch-1.4 "ALL MET" line was a false pass. Corrected in PLAN.md. Root EXPECT lines now require a real success token (`E2E_OK`, `PLAYWRIGHT_OK`, a Test Files line with no failed-count prefix).

## How to continue (driver loop, orchestrated mode)

Read `PLAN.md` first — contract, file-ownership table, and append-only status
log (last lines = exact verification evidence per leaf). Gates live in `gates/`.
This build runs under the unlazy skill's orchestrated mode:

1. Pick the next leaf from the order below. Dispatch a **fresh general subagent**
   whose brief = the contract excerpts in PLAN.md for that leaf + its gates file
   content verbatim + the four passes (implement fully → expert re-read → defect
   hunt → free polish) until every gate has real EVIDENCE.
2. Verify, never trust: `node /Users/justinmiddler/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/leaf-X.md`,
   re-run the leaf's CHECK commands yourself, and adversarially spot-check one
   passed gate (read the actual test assertions).
3. Append one status line to PLAN.md. Dispatch the next leaf.
4. After a branch's last leaf: run `gate-check.mjs gates/node-X.md` (it runs the
   CHECKs incl. full suite) and log it.
5. Only when root gates pass, write the final report with re-measured numbers.

## Done and parent-verified (do not redo)

| Item | Evidence |
|---|---|
| Leaf 1.1.1 publication policy + STIX export gating (F1) | gates/leaf-1.1.1.md 7/7; audit regression tests/publication-policy.test.ts:234 (derived C2 dropped) |
| Leaf 1.1.2 expiry/activity/stale warnings (F2) | gates/leaf-1.1.2.md 7/7; Feodo-offline regressions tests/freshness.test.ts:200,285 |
| Leaf 1.1.3 cluster timestamps & rationale (F3) | gates/leaf-1.1.3.md 7/7; migration 0022; tests/correlate.test.ts (9 tests) |
| Branch 1.1 integration | gates/node-1.1.md 6/6 |
| Leaf 1.2.1 one effective analyst decision (F4) | gates/leaf-1.2.1.md 6/6; audit sequence tests/analyst-state.test.ts:149 |
| Leaf 1.2.2 queue decomposition + enrichment backlog (F5) | gates/leaf-1.2.2.md 7/7; .invalid-vs-KEV fixture tests/priority-queue.test.ts:162-240 |
| Leaf 1.2.3 score definitions & factor naming (F8) | gates/leaf-1.2.3.md 6/6; factor gating packages/scoring/src/index.ts:55-62 |
| Branch 1.2 integration | gates/node-1.2.md 5/5 (driver edit: operations.tsx labels → "Overall confidence") |
| Leaf 1.3.1 canonical entities (F6) | gates/leaf-1.3.1.md 6/6; tests/canonical.test.ts 7 tests (three putEntity campaigns collapse; tenant visibility) |
| Leaf 1.3.2 customer exposure (F7) | gates/leaf-1.3.2.md 6/6; tests/exposure.test.ts 6 tests (empty profile relevance null) |
| Branch 1.3 integration | gates/node-1.3.md 5/5 (full suite + typecheck via gate-check; do not cite suite size until re-measured) |
| Leaf 1.4.1 bulk diagnostics (F9) | gates/leaf-1.4.1.md 6/6; tests/bulk-diagnostics.test.ts 3 tests (accepted=1,duplicates=1,rejected=1). Driver added match_status to GET /v1/workspace/:id/matches |

Baseline was 12 files / 113 tests green + typecheck clean (2026-10-13 15:10).
Suite size grew with each leaf (1.2.3 self-reported 175 tests / 17 files —
re-measure before citing). Every leaf's tests are in `tests/` root: publication-policy,
freshness, correlate, analyst-state, priority-queue, scoring-labels.

## Remaining work, in dispatch order

1. **Leaf 1.4.2 — Requirements & reports ergonomics (F10, P2)** — PLAN.md §10.
   Files: workspace-objects.tsx (criterion labels at :1005, :505), packages/enterprise/src/
   {export,repository}.ts (claims citations, tlp/audience, approval, immutable
   published revisions), packages/schemas/src/enterprise.ts (additive),
   tests/reports.test.ts.
2. **Leaf 1.4.3 — Production readiness register & handoffs (F11, P1)** — PLAN.md
   §11 + scope-boundary section. Docs only: docs/readiness.md (register rows for
   this remediation + explicit open-ops list), docs/intelligence-operations.md
   (downstream-handoff design). Ops-only items get ABANDON lines in
   gates/leaf-1.4.3.md + surfaced in the final report: ThreatFox/URLhaus secrets
   + licensing, production MFA, SSO IdP, alert delivery test, RPO/RTO + retention,
   sustained load, customer acceptance. Also fold in the doc sweeps below.
3. **Branch gates** `gate-check.mjs gates/node-1.4.md` (includes system e2e for
   bulk-pipeline + enterprise-workspace).
4. **Root gates** `gates/root.md`: G1 leaves all checked, G2 branches all
   checked, G3 `pnpm test`, G4 `pnpm typecheck`, G5 `pnpm lint`, G6 `pnpm test:e2e`,
   G7 `pnpm test:playwright`, G8 finding→evidence map (findings 1–11 → leaf gate
   file:line/test name), G9 pre-existing uncommitted work preserved (git status
   must still show migrations/0021_outbox_dispatch_token.sql etc.), G10 report
   with re-measured numbers + all ABANDON lines.

## Carry-forward notes (each is a real decision already made)

- **Shared files are region-serialized**; dispatch leaves strictly sequentially.
  Files with multi-leaf regions: apps/api/src/index.ts, packages/database/src/repository.ts,
  packages/schemas/src/index.ts (additive `// leaf-X.Y.Z additive` blocks only),
  apps/web/components/{investigation,intelligence-card,operations}.tsx,
  packages/enterprise/src/scoring.ts.
- **Never touch pre-existing uncommitted work**: apps/api/src/env.ts,
  docs/deployment.md, docs/operations.md, packages/intel/src/{ingest,optional-feeds}.ts,
  workers/feed-sync/index.ts, tests/{enterprise,feeds,pipeline-reliability}.test.ts,
  wrangler.jsonc, migrations/0021_outbox_dispatch_token.sql (untracked), and the
  canonical/sourceStatements hunks inside packages/database/src/repository.ts.
- **Migration numbers reserved**: 0022 (used, clusters) · 0023 publication_state
  (unused) · 0024 matching state (1.4.1, not yet written) · 0025 canonical
  aliases USED as table `canonical_aliases` (0001 `entity_aliases` is name
  lookup — do not rebuild it) · 0026 environment assets unused (assets live in
  customer_environments JSON) · 0027 workspace revision (1.4.2, optional).
  Never put a literal semicolon inside SQL string values — the migration
  splitter is naive (see 0022's `char(59)` trick). `INSERT INTO workspace_matches VALUES(...)`
  in packages/enterprise/src/automation.ts is positional; adding columns
  without switching those inserts to a named column list breaks SQLite.
- **1.3 behavior now live**: GET /v1/assessments defaults to latest assessment
  per observable (`flat=1` restores the raw list; filters/sort/cursor still
  apply). Library/detail collapse campaigns that share externalId or
  sourceRecordId, visible peers only. Empty environment → exposure applicability
  unknown, relevance null.
- **Stable APIs for downstream leaves**: `freshness()`/`FreshnessState`/
  `reassessmentTrigger()`/`freshEvidenceGate()` (packages/intel/src/freshness.ts),
  `effectiveDecision()`/`effectiveRecommendations()`/`automaticGatesPassed()`/
  `effectiveClassificationSql` (packages/database/src/decision-state.ts),
  `operationalUrgency()` + `urgencySql` (packages/enterprise/src/urgency.ts,
  packages/database/src/assessment-query.ts), `publicationState()`/`publishableClaims()`
  (packages/stix/src/policy.ts).
- **Behavior changes clients should know**: confirm/reject/investigate with
  `field != "assessment"` now 422 INVALID_OVERRIDE; operational STIX is marked
  non-actionable instead of hard-failing; `sort=relevance` wire value now orders
  by urgency (UI label "Highest operational urgency"); tests/system/analyst-workbench.e2e.ts:78
  label updated to "Threat severity".
- **Open follow-ups found by leaves** (fold into 1.4.3 or a root fix):
  1. scripts/demo-data.ts seeds threat_clusters.last_seen with wall clock
     (demo-only; align with observation semantics).
  2. docs/api.md + docs/tip-ux-review.md still describe customer-relevance
     ordering and old labels.
  3. docs/readiness.md "ten labelled synthetic challenges" is imprecise (10
     cases, 9 labelled, 1 deliberately unlabelled) — fix wording in 1.4.3.
  4. scripts/evaluation-challenges.ts literal lacks `caveat:`; strict
     synthetic-dataset refusal in packages/scoring/src/dataset.ts is documented
     but not enforced (add caveat + superRefine to finish).
  5. packages/clef re-implements the ≤14d fresh-evidence gate duplicated in
     decision-state.ts (clef is not web-importable; unify only if trivial).
  6. Scattered `effective_classification ?? malicious.classification` coalescing
     remains in apps/api/src/enterprise.ts:309, packages/enterprise/src/
     {intelligence,scoring}.ts, intelligence-card.tsx, packages/stix/* — semantics
     agree today; owners could switch to effectiveClassificationSql later.
- **Audit-report discrepancy (confirmed)**: the report's claim that the local
  branch "removes case/automation/sighting UI" is NOT true on this branch
  (/cases, /automations, /sightings + APIs all present). Leaf 1.4.3 documents
  the downstream-handoff product design instead of removing anything.
- **Scope boundary**: production ops actions (feed secrets, MFA enforcement, SSO,
  alert delivery, retention, load, customer acceptance) are out of session
  scope — record, don't pretend. Finding 11 closes as "code-side done + ops
  items explicitly registered", stated plainly in the final report.
