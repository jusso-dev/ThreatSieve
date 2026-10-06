import { z } from "zod";
import { AppError } from "../../observability/src/index";
import type { Assessment } from "../../schemas/src/index";
import type { AssessmentFilters } from "../../schemas/src/query";
export const AssessmentView = z.enum(["all", "attention", "review"]);
export type AssessmentView = z.infer<typeof AssessmentView>;
export const attentionPredicate =
  "status!='confirmed' AND (human_review=1 OR COALESCE(json_extract(data,'$.effective_classification'),json_extract(data,'$.malicious.classification'))!='benign')";
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

export const assessmentOrders = {
  newest: { column: "created_at", direction: "DESC" },
  oldest: { column: "created_at", direction: "ASC" },
  confidence: {
    column: "json_extract(data,'$.confidence')",
    direction: "DESC",
  },
  relevance: {
    column: "json_extract(data,'$.customer.relevance')",
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
            ? a.customer.relevance
            : a.created_at,
    }),
  );
}
