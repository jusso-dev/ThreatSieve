# Gates: root — ThreatSieve audit remediation (findings 1–11)

Scope: every finding 1–11 from the 2026-10-13 analyst audit is remediated in
code/tests/docs, or explicitly recorded as open ops work; full suite green.

- [x] G1: All 11 leaf gate files fully checked (no unchecked boxes, no pending evidence).
  CHECK: sh -c 'test $(grep -h "^- \[ \]" gates/leaf-*.md | wc -l) -eq 0 && echo ALL_LEAVES_CHECKED'
  EXPECT: ALL_LEAVES_CHECKED
  EVIDENCE: ALL_LEAVES_CHECKED

- [x] G2: All 4 branch gate files fully checked.
  CHECK: sh -c 'test $(grep -h "^- \[ \]" gates/node-*.md | wc -l) -eq 0 && echo ALL_BRANCHES_CHECKED'
  EXPECT: ALL_BRANCHES_CHECKED
  EVIDENCE: ALL_BRANCHES_CHECKED

- [x] G3: Full unit/integration suite passes after all leaves.
  CHECK: pnpm test 2>&1 | tail -30
  EXPECT: /^\s*Test Files\s+\d+ passed \(\d+\)\s*$/m
  EVIDENCE: Start at  21:15:59 | Duration  94.49s (tests 93%, import 6%)

- [x] G4: Typecheck clean across api, tests/system and web.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK

- [x] G5: Lint clean.
  CHECK: pnpm lint && echo LINT_OK
  EXPECT: LINT_OK
  EVIDENCE: > eslint . | LINT_OK

- [x] G6: System e2e suites pass (bulk-pipeline, investigation, enterprise-workspace at minimum; full run preferred).
  CHECK: pnpm test:e2e && echo E2E_OK
  EXPECT: E2E_OK
  EVIDENCE: Markdown  .e2e/summary.md | E2E_OK

- [x] G7: Playwright analyst regressions pass.
  CHECK: CI=1 pnpm test:playwright && echo PLAYWRIGHT_OK
  EXPECT: PLAYWRIGHT_OK
  EVIDENCE: (node:99860) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set. | (Use `node --trace-warnings ...` to show where the warning was created)

- [x] G8: Finding→evidence map complete: findings 1–11 each cite a leaf gate with a file:line or test name in PLAN.md status log; out-of-scope ops items (feed secrets, MFA/SSO, alert delivery, retention, load, customer acceptance) appear as explicit open items, never silently dropped.
  EVIDENCE: PLAN.md status log line "Finding→evidence map" (2026-10-13 20:45) cites F1 tests/publication-policy.test.ts, F2 tests/freshness.test.ts, F3 tests/correlate.test.ts, F4 tests/analyst-state.test.ts, F5 tests/priority-queue.test.ts, F6 tests/canonical.test.ts, F7 tests/exposure.test.ts, F8 tests/scoring-labels.test.ts, F9 tests/bulk-diagnostics.test.ts, F10 tests/reports.test.ts, F11 docs/readiness.md + gates/leaf-1.4.3.md ABANDON G5-ThreatFox, G5-MFA, G5-SSO, G5-Alert, G5-RPO, G5-Load, G5-Customer. Open ops also in docs/readiness.md "Open ops — remaining, never done".

- [x] G9: Pre-existing uncommitted changes preserved (apps/api/src/env.ts, docs/deployment.md, docs/operations.md, packages/database/src/repository.ts (pre-existing hunks), packages/intel/*, tests/{enterprise,feeds,pipeline-reliability}.test.ts, workers/feed-sync/index.ts, wrangler.jsonc, migrations/0021_outbox_dispatch_token.sql all still present).
  CHECK: git status --short
  EXPECT: /migrations\/0021_outbox_dispatch_token.sql/
  EVIDENCE: ?? tests/reports.test.ts | ?? tests/scoring-labels.test.ts

- [x] G10: Report audit — every number in the final report re-measured at report time (test counts, gate counts), ABANDON lines surfaced.
  EVIDENCE: 2026-10-13 21:16 re-measure. pnpm test captured Test Files 22 passed (22), Tests 194 passed (194); following gate-check G3 PASS (Start at 21:15:59, Duration 94.49s). pnpm test:e2e G6 PASS, .e2e/summary.md "87 passed", 12 files. CI=1 pnpm test:playwright captured 8 passed; gate-check G7 PASS. Leaf boxes checked 69, unchecked 0. Branch boxes checked 23, unchecked 0. Root 10/10 after this box. ABANDON: G5-ThreatFox, G5-MFA, G5-SSO, G5-Alert, G5-RPO, G5-Load, G5-Customer. Scoring independent_group vs mirror flag still open.
