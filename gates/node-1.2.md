# Gates: node 1.2 — Decision & ranking semantics (findings 4, 5, 8)

Scope: one effective analyst decision, an urgency-ranked queue with an
enrichment backlog, and honestly named scores; no sibling regressions.

- [x] G1: Children 1.2.1, 1.2.2, 1.2.3 gates files fully checked.
  CHECK: sh -c 'test $(grep -h "^- \[ \]" gates/leaf-1.2.1.md gates/leaf-1.2.2.md gates/leaf-1.2.3.md | wc -l) -eq 0 && echo CHILDREN_CHECKED'
  EXPECT: CHILDREN_CHECKED
  EVIDENCE: CHILDREN_CHECKED

- [x] G2: End-to-end reproduction of the audit contradiction (finding 4): benign override → confirm → the resulting assessment state (API + rendered wording) shows analyst-confirmed benign, no INVESTIGATE recommendation, and no "confidence gates passed" claim.
  CHECK: pnpm exec vitest run tests/analyst-state.test.ts tests/priority-queue.test.ts tests/scoring-labels.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  19:33:53 | Duration  6.37s (tests 88%, import 9%, transform 2%)

- [x] G3: Full vitest suite green with all three leaves merged.
  CHECK: pnpm test 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  19:34:00 | Duration  62.75s (tests 93%, import 6%)

- [x] G4: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK

- [x] G5: Queue and scores tell one story: the same assessment's severity, evidence confidence, customer relevance and operational urgency are four separately labelled values everywhere they appear; no UI label renders a heuristic 0–100 score without the "/100 heuristic" qualifier.
  CHECK: sh -c 'rg -n "Operational urgency|Evidence confidence" apps/web/components/operations.tsx && rg -n "/100 heuristic" apps/web/components/intelligence-card.tsx'
  EXPECT: /Operational urgency/
  EVIDENCE: 126:              : s.relevance.value + "/100 heuristic"} | 265:                      : s[key].value + "/100 heuristic"}
