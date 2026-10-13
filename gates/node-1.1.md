# Gates: node 1.1 — Publication & freshness (findings 1, 2, 3)

Scope: export eligibility, indicator expiry/activity, and cluster timestamps
compose into one coherent freshness story; no sibling regressions.

- [x] G1: Children 1.1.1, 1.1.2, 1.1.3 gates files fully checked.
  CHECK: sh -c 'test $(grep -h "^- \[ \]" gates/leaf-1.1.1.md gates/leaf-1.1.2.md gates/leaf-1.1.3.md | wc -l) -eq 0 && echo CHILDREN_CHECKED'
  EXPECT: CHILDREN_CHECKED
  EVIDENCE: CHILDREN_CHECKED

- [x] G2: Freshness feeds publication: a synthetic assessment with 220-day-old Feodo "offline" evidence and pending review yields PublicationState.activity in {"stale","expired"}, eligible=false, valid_until in the past or bounded, in one call chain (no duplicated date logic in packages/stix).
  CHECK: pnpm exec vitest run tests/publication-policy.test.ts tests/freshness.test.ts tests/correlate.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  16:55:52 | Duration  7.40s (tests 85%, import 10%, transform 4%)

- [x] G3: Full vitest suite green with all three leaves merged (no sibling regressions).
  CHECK: pnpm test 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  16:56:00 | Duration  53.15s (tests 93%, import 6%)

- [x] G4: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK

- [x] G5: Audit reproduction (finding 1) is a regression test: the export for a pending-review, stale-evidence, 41%-confidence IP never emits indicator_types ["malicious-activity"] in an operational export, and the derived C2 role is dropped when its only evidence is restricted.
  CHECK: pnpm exec vitest run tests/publication-policy.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  16:57:00 | Duration  2.27s (tests 70%, import 19%, transform 11%)

- [x] G6: Cluster "last observed" is never later than the newest supporting evidence observedAt; reprocessing old evidence does not move it (finding 3 regression).
  CHECK: pnpm exec vitest run tests/correlate.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  16:57:02 | Duration  3.94s (tests 93%, import 5%, transform 2%)
