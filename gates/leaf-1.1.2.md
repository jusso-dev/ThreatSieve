# Gates: leaf 1.1.2 — Indicator expiry, activity & stale warnings (finding 2, P1)

Scope: indicator-specific expiry, active/inactive status, last actual
observation, stale warnings, reassessment triggers; fresh evidence required
before recommending blocking.

Contract: PLAN.md "Shared interfaces" §2 (FreshnessState, freshness(), policy
defaults, new reason codes). File ownership row 1.1.2. packages/stix reads
FreshnessState via publicationState (leaf 1.1.1 already merged) — this leaf
exposes the module and drives UI + recommendations; it does not edit packages/stix.

- [x] G1: packages/intel/src/freshness.ts exports freshness() with the pinned FreshnessState shape and the 30d/90d/unknown policy.
  CHECK: sh -c 'rg -n "export function freshness|export interface FreshnessState" packages/intel/src/freshness.ts'
  EXPECT: /export function freshness/
  EVIDENCE: 18:export interface FreshnessState { | 62:export function freshness(

- [x] G2: Regression test for the audit case: one 220-day-old Feodo record whose original status was "offline" → activity is "expired"/"stale", never "active"; historical malicious association is retained but last_observed equals the evidence observedAt (not now); reassessment trigger fires (reason EXPIRED_INDICATOR).
  CHECK: pnpm exec vitest run tests/freshness.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) | Tests  17 passed (17)

- [x] G3: Recommended action "block" is downgraded to monitor/hunt with reason FRESH_EVIDENCE_REQUIRED unless evidence is ≤14 days fresh and the assessment is not awaiting review; test covers both directions (fresh evidence keeps block).
  CHECK: pnpm exec vitest run tests/freshness.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) | Tests  17 passed (17)

- [x] G4: New reason codes exist in packages/schemas reasonCodes: FRESH_EVIDENCE_REQUIRED, EXPIRED_INDICATOR, HISTORICAL_ASSOCIATION_ONLY.
  CHECK: sh -c 'rg -n "FRESH_EVIDENCE_REQUIRED|EXPIRED_INDICATOR|HISTORICAL_ASSOCIATION_ONLY" packages/schemas/src/index.ts'
  EXPECT: /HISTORICAL_ASSOCIATION_ONLY/
  EVIDENCE: 245:  "EXPIRED_INDICATOR", | 246:  "HISTORICAL_ASSOCIATION_ONLY",

- [x] G5: UI shows activity status, "last actual observation" (evidence-derived), and a stale/expired warning badge on the assessment detail and intelligence card; a "reassess" trigger is offered for expired indicators.
  CHECK: sh -c 'rg -n "last_observed|Last actual observation|stale|expired" apps/web/components/investigation.tsx apps/web/components/intelligence-card.tsx | head -8'
  EXPECT: /stale|expired/
  EVIDENCE: apps/web/components/investigation.tsx:154: {freshnessState.activity === "expired" | apps/web/components/investigation.tsx:156: : freshnessState.activity === "stale"

- [x] G6: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK

- [x] G7: Expert re-read done: freshness logic distinguishes observed/retrieved/processed per PLAN conventions; no wall-clock value is ever presented as an observation.
  EVIDENCE: freshness.ts:69,74-77 derive first/last_observed + valid_until from evidence observedAt only (now at :66 measures age, never stored); intelligence-card.tsx:154 / investigation.tsx:334 render "Last actual observation" from freshnessState.last_observed (createdAt fallback removed; "Assessed" keeps created_at as processing time); unknown renders as "Unknown"/"unknown", never 0 or fresh.
