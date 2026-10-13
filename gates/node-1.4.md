# Gates: node 1.4 — Workflow UX & production acceptance (findings 9, 10, 11)

Scope: background workflows diagnose themselves, requirements/reports work for
analysts, and production acceptance is honestly registered; no sibling regressions.

- [x] G1: Children 1.4.1, 1.4.2, 1.4.3 gates files fully checked (or their ABANDON lines present and surfaced).
  CHECK: sh -c 'test $(grep -h "^- \[ \]" gates/leaf-1.4.1.md gates/leaf-1.4.2.md gates/leaf-1.4.3.md | wc -l) -eq 0 && echo CHILDREN_CHECKED'
  EXPECT: CHILDREN_CHECKED
  EVIDENCE: CHILDREN_CHECKED

- [x] G2: Bulk three-line audit case (one valid unique, one duplicate, one invalid) reports exactly those three line outcomes end to end: API result shape and UI both show accepted=1, duplicates=1, rejected=1 with the line-level error.
  CHECK: pnpm exec vitest run tests/bulk-diagnostics.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  20:42:01 | Duration  8.15s (tests 90%, import 7%, transform 3%)

- [x] G3: Requirement/watchlist matching exposes queued/running/complete/failed plus last-evaluated time; no bare "No matches yet" without progress state.
  CHECK: sh -c 'rg -n "last_evaluated_at|match_status" packages/enterprise/src/intelligence.ts apps/web/components/workspace-activity.tsx'
  EXPECT: /last_evaluated_at/
  EVIDENCE: apps/web/components/workspace-activity.tsx:115:          {data.last_evaluated_at | apps/web/components/workspace-activity.tsx:116:            ? " · last evaluated " + relativeTime(data.last_evaluated_

- [x] G4: Full vitest suite green with all three leaves merged.
  CHECK: pnpm test 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  20:42:09 | Duration  100.19s (tests 93%, import 7%)

- [x] G5: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK

- [x] G6: Readiness register and handoff design present and consistent with this remediation (docs/readiness.md, docs/intelligence-operations.md).
  CHECK: sh -c 'rg -n "handoff|Handoff" docs/intelligence-operations.md && rg -n "Publication|freshness|expir" docs/readiness.md'
  EXPECT: /handoff|Handoff/
  EVIDENCE: 17:| Publication policy     | Operational STIX export drops derived claims (for example C2 role) when supporting evidence is restricted; non-eligible indicators are marked non-actionable rather than h

- [x] G7: System e2e for the touched flows (bulk-pipeline, enterprise-workspace) passes.
  CHECK: pnpm test:e2e tests/system/bulk-pipeline.e2e.ts tests/system/enterprise-workspace.e2e.ts && echo E2E_OK
  EXPECT: E2E_OK
  EVIDENCE: pending
  EVIDENCE: Markdown  .e2e/summary.md | E2E_OK
