import { z } from "zod";
import { AppError } from "../../observability/src/index";
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
