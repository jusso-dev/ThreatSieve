import { z } from "zod";
import { AppError } from "../../observability/src/index";
import type { Assessment } from "../../schemas/src/index";
import type { AssessmentFilters } from "../../schemas/src/query";
import { effectiveClassificationSql } from "./decision-state";
import {
  operationalUrgency,
  URGENCY_WEIGHTS,
  URGENCY_UNKNOWN,
  URGENCY_ROUND_DIGITS,
  URGENCY_PRIORITY_IMPACT,
  URGENCY_FRESHNESS_ACTIVITY,
  URGENCY_REVIEW_STATE,
} from "../../enterprise/src/urgency";
import {
  STALE_AFTER_DAYS,
  EXPIRES_AFTER_DAYS,
} from "../../intel/src/freshness";
export const AssessmentView = z.enum(["all", "attention", "review"]);
export type AssessmentView = z.infer<typeof AssessmentView>;
// Queue placement derives from the same effective decision as the wording
// (decision-state.ts): a confirmed assessment is resolved and leaves the
// queues, and an analyst benign override leaves the attention queue once
// confirmed. The effective classification expression lives only in
// decision-state.ts so no surface re-embeds the coalescing.
export const attentionPredicate =
  "status!='confirmed' AND (human_review=1 OR " +
  effectiveClassificationSql +
  "!='benign')";
export const reviewPredicate = "status!='confirmed' AND human_review=1";
export function assessmentFilter(view: AssessmentView = "all") {
  return view === "attention"
    ? attentionPredicate
    : view === "review"
      ? reviewPredicate
      : "1=1";
}
export function assessmentCursor(
  cursor?: string,
): [string | null, string | null] {
  if (!cursor) return [null, null];
  try {
    return z
      .tuple([z.iso.datetime(), z.string().min(1).max(200)])
      .parse(JSON.parse(atob(cursor)));
  } catch {
    throw new AppError(
      "INVALID_CURSOR",
      400,
      "Invalid assessment pagination cursor",
    );
  }
}

/** Assessment carries at least one evidence record. */
export const evidencePresentPredicate =
  "COALESCE(json_array_length(json_extract(data,'$.evidence')),0)>0";
/** Assessment carries zero evidence records (insufficient evidence). */
export const evidenceAbsentPredicate =
  "COALESCE(json_array_length(json_extract(data,'$.evidence')),0)=0";

// --- leaf-1.2.2 operational urgency, computed in SQL -------------------------
//
// The actionable queue is ordered by operational urgency. The contract allows
// SQL or post-fetch TypeScript; SQL is the choice here so ORDER BY and keyset
// pagination (`sortedCursor` `(value, id)` pairs) run in one query without
// over-fetching. `urgencySql` mirrors `operationalUrgency()`
// (packages/enterprise/src/urgency.ts) exactly — same constants (imported
// above), same term order, same rounding (4 decimals; see
// URGENCY_ROUND_DIGITS for why 3 is tie-unsafe) — over the `assessments`
// columns `data`, `status` and `human_review`. It is the no-`ctx` form:
// exploitation comes from assessment evidence (`data.kev`, set by the CISA KEV
// feed), and unknown inputs contribute the neutral midpoint, never zero.
// The keyset cursor boundary is resolved against this same expression inside
// SQL (repository.assessments), so pagination is exact even if TypeScript and
// SQLite rounding ever disagree at a bucket edge.
// tests/priority-queue.test.ts asserts SQL and TypeScript agree row by row.
const URGENCY_EVIDENCE = "json_extract(data,'$.evidence')";
const URGENCY_LAST_OBSERVED_JD = `(SELECT MAX(julianday(json_extract(u_e.value,'$.observedAt'))) FROM json_each(${URGENCY_EVIDENCE}) u_e WHERE julianday(json_extract(u_e.value,'$.observedAt'))<=julianday('now'))`;
const URGENCY_UNDATED = `EXISTS(SELECT 1 FROM json_each(${URGENCY_EVIDENCE}) u_e WHERE julianday(json_extract(u_e.value,'$.observedAt')) IS NULL)`;
const URGENCY_FUTURE = `EXISTS(SELECT 1 FROM json_each(${URGENCY_EVIDENCE}) u_e WHERE julianday(json_extract(u_e.value,'$.observedAt'))>julianday('now'))`;
const URGENCY_OFFLINE = `EXISTS(SELECT 1 FROM json_each(${URGENCY_EVIDENCE}) u_e WHERE trim(lower(COALESCE(json_extract(u_e.value,'$.data.status'),'')))='offline' OR trim(lower(COALESCE(json_extract(u_e.value,'$.data.url_status'),'')))='offline' OR trim(lower(COALESCE(json_extract(u_e.value,'$.data.source_status'),'')))='offline')`;
const URGENCY_KEV = `EXISTS(SELECT 1 FROM json_each(${URGENCY_EVIDENCE}) u_e WHERE json_extract(u_e.value,'$.data.kev')=1)`;

// FreshnessState tiers (leaf 1.1.2 policy: stale past 30d, expired past 90d,
// undated/offline never "active"). Unknown activity → neutral midpoint.
const URGENCY_FRESHNESS_SQL = `(CASE
  WHEN ${URGENCY_LAST_OBSERVED_JD} IS NULL THEN ${URGENCY_UNKNOWN}
  WHEN julianday('now')-${URGENCY_LAST_OBSERVED_JD} > ${EXPIRES_AFTER_DAYS} THEN ${URGENCY_FRESHNESS_ACTIVITY.expired}
  WHEN julianday('now')-${URGENCY_LAST_OBSERVED_JD} > ${STALE_AFTER_DAYS} THEN ${URGENCY_FRESHNESS_ACTIVITY.stale}
  WHEN ${URGENCY_UNDATED} OR ${URGENCY_OFFLINE} OR ${URGENCY_FUTURE} THEN ${URGENCY_FRESHNESS_ACTIVITY.stale}
  ELSE ${URGENCY_FRESHNESS_ACTIVITY.active} END)`;

export const urgencySql = `ROUND(${URGENCY_WEIGHTS.assetImpact}*(0.7*(CASE json_extract(data,'$.customer.priority') WHEN 'critical' THEN ${URGENCY_PRIORITY_IMPACT.critical} WHEN 'high' THEN ${URGENCY_PRIORITY_IMPACT.high} WHEN 'medium' THEN ${URGENCY_PRIORITY_IMPACT.medium} ELSE ${URGENCY_PRIORITY_IMPACT.low} END) + 0.3*MIN(MAX(COALESCE(json_extract(data,'$.customer.exposedAssets'),0),0)/10.0,1.0)) + ${URGENCY_WEIGHTS.exposure}*(0.5*MIN(MAX(COALESCE(json_extract(data,'$.customer.relevance'),0),0),1.0) + 0.5*(CASE WHEN json_extract(data,'$.customer.observed') THEN 1.0 ELSE 0.0 END)) + ${URGENCY_WEIGHTS.freshness}*${URGENCY_FRESHNESS_SQL} + ${URGENCY_WEIGHTS.exploitation}*(CASE WHEN ${URGENCY_KEV} THEN 1.0 ELSE ${URGENCY_UNKNOWN} END) + ${URGENCY_WEIGHTS.evidenceConfidence}*(CASE WHEN ${evidencePresentPredicate} THEN MIN(MAX(COALESCE(json_extract(data,'$.confidence'),0),0),1.0) ELSE ${URGENCY_UNKNOWN} END) + ${URGENCY_WEIGHTS.reviewState}*(CASE WHEN status='confirmed' THEN ${URGENCY_REVIEW_STATE.settled} WHEN human_review=1 OR status='needs-investigation' THEN ${URGENCY_REVIEW_STATE.awaiting_review} ELSE ${URGENCY_REVIEW_STATE.undecided} END), ${URGENCY_ROUND_DIGITS})`;

export const assessmentOrders = {
  newest: { column: "created_at", direction: "DESC" },
  oldest: { column: "created_at", direction: "ASC" },
  confidence: {
    column: "json_extract(data,'$.confidence')",
    direction: "DESC",
  },
  // leaf-1.2.2: the queue ordering is operational urgency, never the raw
  // model relevance score (audit finding 5). See `urgencySql` above.
  relevance: {
    column: urgencySql,
    direction: "DESC",
  },
} as const;

export function sortedCursor(
  cursor: string | undefined,
  sort: AssessmentFilters["sort"],
): [string | number | null, string | null] {
  if (!cursor) return [null, null];
  try {
    const parsed: unknown = JSON.parse(atob(cursor));
    // Preserve the original newest-first API cursor format.
    if (Array.isArray(parsed)) {
      if (sort !== "newest") throw new Error("Sort mismatch");
      return assessmentCursor(cursor);
    }
    const value = z
      .object({
        sort: z.literal(sort),
        value: z.union([z.iso.datetime(), z.number().min(0).max(1)]),
        id: z.string().min(1).max(200),
      })
      .parse(parsed);
    if (
      (sort === "newest" || sort === "oldest") !==
      (typeof value.value === "string")
    )
      throw new Error("Cursor value mismatch");
    return [value.value, value.id];
  } catch {
    throw new AppError(
      "INVALID_CURSOR",
      400,
      "This page no longer matches your sort. Return to the first page.",
    );
  }
}

export function encodeAssessmentCursor(
  a: Assessment,
  sort: AssessmentFilters["sort"],
) {
  return btoa(
    JSON.stringify({
      sort,
      id: a.assessment_id,
      value:
        sort === "confidence"
          ? a.confidence
          : sort === "relevance"
            ? // Rounded urgency (same quantisation as urgencySql) — carried as
              // a hint and fallback; the keyset boundary itself is resolved
              // inside SQL against the cursor row (repository.assessments).
              operationalUrgency(a).urgency
            : a.created_at,
    }),
  );
}
