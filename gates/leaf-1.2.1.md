# Gates: leaf 1.2.1 — One effective analyst decision (finding 4, P1)

Scope: one effective decision drives actions, queue placement, publication and
wording; model output kept as history; "analyst confirmed" distinct from
"automatic evidence gates passed".

Contract: PLAN.md "Shared interfaces" §4 (effectiveDecision(), effectiveRecommendations(),
wording contract). File ownership row 1.2.1. Reference contradiction: benign
override → confirm → page still recommends INVESTIGATE, says unknown is
appropriate, claims confidence gates passed at 0% confidence with zero evidence.

- [x] G1: packages/database/src/decision-state.ts exports effectiveDecision() and effectiveRecommendations() with the pinned shapes; Repository.feedback and the assessment query predicates use them (single source of truth).
  CHECK: sh -c 'rg -n "export function effectiveDecision|export function effectiveRecommendations" packages/database/src/decision-state.ts'
  EXPECT: /export function effectiveDecision/
  EVIDENCE: 31:export function effectiveDecision(a: Assessment): { | 121:export function effectiveRecommendations(

- [x] G2: Regression test reproduces the audit contradiction: create assessment → benign override (modify) → confirm → resulting state has analyst-confirmed benign wording source, recommended actions consistent with the decision (no INVESTIGATE), queue placement consistent (out of attention queue), and no claim that automatic gates passed; model history (a.malicious, model classification) untouched.
  CHECK: pnpm exec vitest run tests/analyst-state.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) | Tests  7 passed (7)

- [x] G3: UI wording: investigation.tsx renders "Analyst confirmed …" for analyst decisions and reserves "confidence gates passed"/equivalents for automatic gates only; the two are never conflated on one card.
  CHECK: sh -c 'rg -n "Analyst confirmed|analyst_confirmed" apps/web/components/investigation.tsx | head -4'
  EXPECT: /Analyst confirmed|analyst_confirmed/
  EVIDENCE: 271:              ? "Analyst confirmed: " + decision.classification

- [x] G4: tests/decisions.test.ts updated where feedback semantics changed and green.
  CHECK: pnpm exec vitest run tests/decisions.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) | Tests  13 passed (13)

- [x] G5: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: tsc --noEmit (all three projects) | TYPECHECK_OK

- [x] G6: Expert re-read done: a second analyst decision (or confirmation after modification) yields exactly one effective decision at a time; audit trail (analyst_feedback rows) retains full history.
  EVIDENCE: "✓ tests/analyst-state.test.ts > a second analyst decision replaces the first while the audit trail keeps every step" — effectiveDecision returns only the latest decision (decidedAt = latest analyst_decision.createdAt) and analyst_feedback keeps both rows ("benign","malicious") in order; confirm-after-modification resolves the same single decision; feedback region re-read (repository.ts) keeps revision CAS / analyst_feedback / cache clearing / export-job machinery untouched.
