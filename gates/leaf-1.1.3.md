# Gates: leaf 1.1.3 — Cluster observation timestamps & rationale (finding 3, P1)

Scope: separate observed/retrieved/processed timestamps for clusters, derive
observation bounds from evidence, show grouping rationale, distinguish shared
malware association from coordinated activity.

Contract: PLAN.md "Shared interfaces" §3 (migration 0022 columns, last_seen
semantics, rationale format). File ownership row 1.1.3. Reference bug:
workers/correlate/index.ts:35 (last_seen bound to processing `now`; name year
from processing date; on-conflict update touches only last_seen; confidence
frozen at first write as ev.confidence * 0.7).

- [x] G1: migrations/0026_cluster_observation.sql adds first_observed, last_observed, last_processed_at, grouping_key, rationale to threat_clusters and is applied cleanly.
  CHECK: sh -c 'rg -n "last_processed_at|grouping_key|rationale" migrations/0026_cluster_observation.sql && pnpm db:validate >/dev/null 2>&1 && echo DB_OK'
  EXPECT: DB_OK
  EVIDENCE: DB_OK (rg: line 7 CREATE TABLE threat_clusters (... first_observed TEXT, last_observed TEXT, last_processed_at TEXT, grouping_key TEXT, rationale TEXT); migration applied by db:validate and by tests/correlate.test.ts migration-0022 backfill test)

- [x] G2: Correlate derives last_seen/first_observed from evidence observedAt bounds and writes last_processed_at=now; reprocessing identical old evidence leaves last_seen unchanged. Regression test covers the reprocess case and the "220-day-old evidence must not look fresh" case.
  CHECK: pnpm exec vitest run tests/correlate.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) / Tests  9 passed (9) — incl. "220-day-old evidence must not look fresh" (bounds == evidence observedAt, last_processed_at == wall clock) and "reprocessing identical old evidence leaves observation bounds unchanged" (last_seen unchanged after 220 simulated days)

- [x] G3: Cluster confidence is recomputed from all member evidence on every run (documented formula, e.g. max or evidence-weighted), not frozen at ev.confidence * 0.7 of the first writer; grouping rationale string recorded per PLAN §3 format and including record/source counts.
  CHECK: sh -c 'rg -n "rationale" workers/correlate/index.ts | head -4'
  EXPECT: /rationale/
  EVIDENCE: 57:/** Pinned rationale format: "<grouping kind> <key>; N evidence records from M sources". */ — formula documented at workers/correlate/index.ts:19-33 (confidence = 0.7 * mean of all member-evidence confidence, recomputed each run); test "confidence is recomputed from all member evidence, not frozen at the first writer's ev.confidence * 0.7" passes

- [x] G4: The common-malware-family-only grouping is labelled as shared association: rationale/cluster description distinguishes "shared malware association" from "coordinated activity", and the existing non-attribution disclaimer is retained.
  CHECK: pnpm exec vitest run tests/correlate.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) / Tests  9 passed (9) — incl. "shared malware association is labelled as association, not coordinated activity, and keeps the non-attribution disclaimer" (description asserts "shared malware association", "NOT evidence of coordinated activity", "This is not a confirmed campaign or actor attribution."); UI note on apps/web/app/clusters/page.tsx for malware: grouping keys

- [x] G5: API GET /v1/clusters returns the new fields; clusters page shows "Last observed" from evidence bounds, a separate "Last processed" value, and the grouping rationale.
  CHECK: sh -c 'rg -n "last_processed_at|rationale" apps/api/src/index.ts apps/web/app/clusters/page.tsx | head -6'
  EXPECT: /rationale/
  EVIDENCE: apps/web/app/clusters/page.tsx:76: Grouping: {c.rationale ?? "Rationale unknown"} (same output shows page.tsx:16 last_processed_at field and page.tsx:66-67 Last processed row; apps/api/src/index.ts:882 SELECT lists first_observed,last_observed,last_processed_at,grouping_key,rationale)

- [x] G6: Typecheck clean and db:validate green.
  CHECK: sh -c 'pnpm typecheck && pnpm db:validate >/dev/null 2>&1 && echo LEAF113_OK'
  EXPECT: LEAF113_OK
  EVIDENCE: LEAF113_OK

- [x] G7: Expert re-read done: no processing/retrieval timestamp can leak into an observation field anywhere in this leaf's code; name year derivation uses observation date.
  EVIDENCE: Re-read of workers/correlate/index.ts, migrations/0026_cluster_observation.sql, apps/api/src/index.ts clusters region, apps/web/app/clusters/page.tsx: sole wall clock is workers/correlate/index.ts:97 `new Date().toISOString()` bound only to last_processed_at (bind order proven by the 220-day test asserting last_processed_at == processing time and last_seen == observedAt); migration bounds are MIN/MAX(evidence.observed_at) only, first_seen/last_seen copy first_observed/last_observed, last_processed_at stays NULL on backfill; API/web are read/display-only (page.tsx new Date() formats an observation value for display); name year from firstObserved (workers/correlate/index.ts:144, test "cluster name year derives from the earliest observation, not the processing date")
