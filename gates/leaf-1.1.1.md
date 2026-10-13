# Gates: leaf 1.1.1 — Publication policy & STIX export gating (finding 1, P1)

Scope: central publication policy so STIX export can never turn pending
intelligence into actionable indicators; research vs operational export
separation; derived-data rights; expiry/retraction fields on the export.

Contract: PLAN.md "Shared interfaces" §1 (PublicationAudience, PublicationState,
publicationState(), exportStix options.audience). File ownership row 1.1.1.
Caller updates: workers/export/index.ts, packages/enterprise/src/export.ts,
scripts/seed.ts, tests all pass `audience: "research"` unless testing operational.
Reference failure case: /Users/justinmiddler/Downloads/assess_a41f5946-1947-4b12-8eb2-0ed467bcba67.stix.json
(pending review, stale evidence, 41% confidence, IP 162.243.103.246 exported as
malicious-activity with C2 role after restricted evidence stripping).

- [x] G1: packages/stix/src/policy.ts exports publicationState() with the pinned PublicationState shape.
  CHECK: sh -c 'rg -n "export function publicationState|export interface PublicationState|export type PublicationAudience" packages/stix/src/policy.ts'
  EXPECT: /export function publicationState/
  EVIDENCE: packages/stix/src/policy.ts:16 `export type PublicationAudience = "research" | "operational";`; :17 `export interface PublicationState {`; :88 `export function publicationState(`

- [x] G2: Regression test reproduces the audit case: assessment with pending review + stale evidence + 41% confidence + restricted C2 evidence → operational export has no indicator_types ["malicious-activity"], carries x_threatsieve_approved_for_operational_use=false, x_threatsieve_publication_state, valid_until and revoked fields, and the derived C2/malware claims whose only support was restricted evidence are absent; the research export keeps model history and the review flag.
  CHECK: pnpm exec vitest run tests/publication-policy.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: `Test Files  1 passed (1)` / `Tests  13 passed (13)` — incl. "marks the operational export non-actionable and drops restricted-derived claims" and "keeps model history and the review flag in the research export"

- [x] G3: Operational eligibility rule enforced (all of: not pending review, ≥1 redistributable evidence, non-stale evidence, confidence ≥ 0.5) as one function used by exportStix and exportAssessment — no duplicated rule in callers.
  CHECK: sh -c 'rg -n "eligible" packages/stix/src/policy.ts packages/stix/src/index.ts workers/export/index.ts | head -8'
  EXPECT: /eligible/
  EVIDENCE: policy.ts:131 `eligible: reasons.length === 0,` (the single rule); packages/stix/src/index.ts:101/123 consume `state.eligible`; workers/export/index.ts:33 comment routes exportAssessment through exportStix → publicationState (no rule in callers)

- [x] G4: GET /v1/assessments/:id/stix accepts ?audience=research|operational (default research) and never returns an operational-actionable bundle for non-eligible assessments (contract: export the bundle marked non-actionable — do not hard-fail; supersedes the earlier "reject with error code" wording in this file).
  CHECK: sh -c 'rg -n "audience" apps/api/src/index.ts | head -6'
  EXPECT: /audience/
  EVIDENCE: apps/api/src/index.ts:613 `const audience = z.enum(["research","operational"]).default("research").parse(c.req.query("audience") ?? "research")`; :620 `exportStix(a, { audience })` — covered by test "never returns an operational-actionable bundle for non-eligible assessments" (200 + approved_for_operational_use=false + no ["malicious-activity"])

- [x] G5: Existing export tests updated and green: tests/decisions.test.ts + tests/integration.test.ts (export assertions) pass with the new exportStix signature.
  CHECK: pnpm exec vitest run tests/decisions.test.ts tests/integration.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: `Test Files  2 passed (2)` / `Tests  34 passed (34)`

- [x] G6: Typecheck clean (packages, tests/system, web).
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: TYPECHECK_OK

- [x] G7: Expert re-read done: policy reads like one publication authority (review status, permitted evidence, derived-data rights, expiry, revocation in one place); no caller can bypass it to produce an operational bundle.
  EVIDENCE: policy.ts owns awaitingReview (:59), permittedEvidence (:47), revokedByAnalyst (:67), expiry/activity/valid_until (:102-116), and publishableClaims derived-data rights (:164) — exportStix (packages/stix/src/index.ts:62) only renders these verdicts and its `audience` option is REQUIRED (typed `PublicationAudience`), so every caller (apps/api route, workers/export, enterprise/export, seed, tests) must declare the audience and operational bundles always pass through publicationState/publishableClaims. Full suite after refactor: 126 passed (13 files).
