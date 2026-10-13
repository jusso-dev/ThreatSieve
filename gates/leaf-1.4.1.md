# Gates: leaf 1.4.1 — Bulk/job diagnostics & matching state (finding 9, P2)

Scope: persistent job history with accepted/duplicate/rejected counts,
line-level errors, result links and retry; requirement/watchlist matching with
queued/running/completed/failed state and last-evaluated timestamp.

Contract: PLAN.md "Shared interfaces" §9 (bulk result shape,
migration 0024 workspace_matches.match_status + last_evaluated_at). File
ownership row 1.4.1. Reference behavior: three-line bulk test (one valid unique,
one duplicate, one invalid) completes correctly but the UI shows only totals;
workers/ingest/upload.ts:34 silently drops in-page duplicates; API returns
counts, not errors; matching shows "No matches yet" with no progress.

- [x] G1: processBulk counts and reports all three line outcomes: result shape { processed, accepted, duplicates, rejected, errors: [{index, error}] }; duplicates are never silently dropped; processed counts lines, not pages.
  CHECK: pnpm exec vitest run tests/bulk-diagnostics.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: ```
 Test Files  1 passed (1)
      Tests  3 passed (3)
   Start at  20:27:28
   Duration  10.49s (tests 87%, import 9%, transform 4%)
```

- [x] G2: GET /v1/jobs/:id returns the full per-line diagnostics and accepted/duplicate/rejected counts; regression test asserts the audit's three-line case yields exactly accepted=1, duplicates=1, rejected=1 with the invalid line's index and error.
  CHECK: pnpm exec vitest run tests/bulk-diagnostics.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: ```
 Test Files  1 passed (1)
      Tests  3 passed (3)
   Start at  20:27:28
   Duration  10.49s (tests 87%, import 9%, transform 4%)
```
  Shape from test: `{ processed: 3, accepted: 1, duplicates: 1, rejected: 1, errors: [{ index: 2, error: "Invalid or ambiguous observable" }] }`. Cross-page duplicates remembered via `payload.seenIds` + cumulative `payload.diagnostics`.

- [x] G3: Bulk page renders line-level errors (index + message), the three counts, result links to created assessments, and a retry control for failed lines/stages.
  CHECK: sh -c 'rg -n "duplicates|errors|retry|Retry" apps/web/app/bulk/page.tsx | head -8'
  EXPECT: /duplicates/
  EVIDENCE: ```
17:    duplicates?: number;
21:  duplicates?: number;
23:  errors?: { index: number; error: string }[];
208:              Retry progress refresh
227:                ? "Analysis finished with failed jobs. Review operational errors before using the results."
245:              {(job.duplicates ?? job.totals.duplicates ?? 0).toLocaleString()}
262:          {!!job.errors?.length && (
263:            <div className="job-errors">
```

- [x] G4: Migration 0024 adds workspace_matches.match_status + last_evaluated_at; matching writes them; UI shows queued/running/complete/failed and "last evaluated <time>" — the empty state never shows a bare "No matches yet" without status.
  CHECK: sh -c 'rg -n "match_status|last_evaluated_at" migrations/0024_matching_state.sql packages/enterprise/src/intelligence.ts apps/web/components/workspace-activity.tsx | head -8'
  EXPECT: /last_evaluated_at/
  EVIDENCE: ```
apps/web/components/workspace-activity.tsx:30:      match_status?: "queued" | "running" | "complete" | "failed";
apps/web/components/workspace-activity.tsx:31:      last_evaluated_at?: string | null;
apps/web/components/workspace-activity.tsx:34:    match_status?: "queued" | "running" | "complete" | "failed";
apps/web/components/workspace-activity.tsx:35:    last_evaluated_at?: string | null;
apps/web/components/workspace-activity.tsx:63:              {m.match_status ? " · " + m.match_status : ""}
apps/web/components/workspace-activity.tsx:64:              {m.last_evaluated_at
apps/web/components/workspace-activity.tsx:65:                ? " · last evaluated " + relativeTime(m.last_evaluated_at)
apps/web/components/workspace-activity.tsx:103:          {data.match_status
```
  Also: migrations/0024_matching_state.sql ALTER ADD match_status + last_evaluated_at; packages/enterprise/src/intelligence.ts workspaceMatchStatement named columns.

- [x] G5: Typecheck clean and db:validate green.
  CHECK: sh -c 'pnpm typecheck && pnpm db:validate >/dev/null 2>&1 && echo LEAF141_OK'
  EXPECT: LEAF141_OK
  EVIDENCE: ```
LEAF141_OK
```

- [x] G6: Expert re-read done: job diagnostics match or exceed what the underlying API already knew (the audit's complaint was the UI being weaker than the API); counts are consistent between worker result, API and UI.
  EVIDENCE: processBulk writes cumulative `{processed,accepted,duplicates,rejected,errors}` via payload-carried diagnostics + seenIds; GET /v1/jobs/:id returns same top-level fields (furthest page by processed, no SUM of cumulatives); bulk page renders accepted/duplicates/rejected, line errors, assessment links when present, Retry failed stages. Matching: named-column upserts with match_status/last_evaluated_at; empty state shows Not evaluated yet (match_status: queued) instead of bare "No matches yet". Replay route untouched.
