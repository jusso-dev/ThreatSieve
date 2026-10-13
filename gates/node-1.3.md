# Gates: node 1.3 — Identity & exposure (findings 6, 7)

Scope: canonical entities with source assertions underneath, and customer
exposure claims that never exceed the environment profile; no sibling regressions.

- [x] G1: Children 1.3.1, 1.3.2 gates files fully checked.
  CHECK: sh -c 'test $(grep -h "^- \[ \]" gates/leaf-1.3.1.md gates/leaf-1.3.2.md | wc -l) -eq 0 && echo CHILDREN_CHECKED'
  EXPECT: CHILDREN_CHECKED
  EVIDENCE: CHILDREN_CHECKED

- [x] G2: The audit's duplicate cases collapse canonically: one MITRE campaign seen via MITRE/TAXII/MISP shows as one canonical entity with three source assertions flagged as mirrors, and one CVE occupies one priority slot with expandable assessment history.
  CHECK: pnpm exec vitest run tests/canonical.test.ts tests/exposure.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  20:14:31 | Duration  7.97s (tests 88%, import 9%, transform 3%)

- [x] G3: With an empty environment profile, no UI or API surface claims customer exposure: CVE cards read "applicability unknown", relevance is null/unknown rather than 0%, and KEV status is labelled "known exploited" not "your exposure".
  CHECK: pnpm exec vitest run tests/exposure.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  20:14:39 | Duration  2.11s (tests 67%, import 21%, transform 11%)

- [x] G4: Full vitest suite green with both leaves merged.
  CHECK: pnpm test 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  20:14:41 | Duration  73.48s (tests 94%, import 6%)

- [x] G5: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK
