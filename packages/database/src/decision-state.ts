import type { Assessment, ThreatRole } from "../../schemas/src/index";
import { freshness } from "../../intel/src/freshness";

/**
 * One effective decision per assessment (finding 4: contradictory analyst
 * state). An analyst decision (`effective_classification` / `effective_role`)
 * supersedes the model output; otherwise the model's own classification is the
 * effective decision. The model's original output (`malicious`, `confidence`,
 * `confidence_factors`, `models`, `runs`, …) is history and is never
 * overwritten — these helpers only read it.
 *
 * Every surface — recommended actions, queue placement, publication and UI
 * wording — derives from the same effective decision via this module.
 */

export type EffectiveClassification =
  | "malicious"
  | "suspicious"
  | "benign"
  | "unknown";

/**
 * SQL expression over the `assessments.data` JSON column for the effective
 * classification. SQL predicates (queue placement, filters, summaries) must
 * use this instead of re-embedding the coalescing so the whole surface agrees
 * with `effectiveDecision()`.
 */
export const effectiveClassificationSql =
  "COALESCE(json_extract(data,'$.effective_classification'),json_extract(data,'$.malicious.classification'))";

export function effectiveDecision(a: Assessment): {
  classification: EffectiveClassification;
  role: ThreatRole | null;
  source: "analyst" | "model";
  decidedAt: string | null;
} {
  const analystDecided =
    a.effective_classification !== undefined || a.effective_role !== undefined;
  return {
    classification: a.effective_classification ?? a.malicious.classification,
    role: a.effective_role ?? a.role.value ?? null,
    source: analystDecided ? "analyst" : "model",
    decidedAt: analystDecided
      ? (a.analyst_decision?.createdAt ?? a.updated_at ?? null)
      : a.created_at,
  };
}

/**
 * "Confidence gates passed" is a claim about AUTOMATIC gates only: the model's
 * own thresholds accepted this assessment without any analyst involvement
 * (`human_review` false by threshold). An analyst-decided assessment is a
 * human judgment, never a gate result, and an assessment with zero evidence or
 * zero confidence can never pass automatic gates.
 */
export function automaticGatesPassed(a: Assessment): boolean {
  return (
    a.status === "pending" &&
    !a.human_review &&
    effectiveDecision(a).source === "model" &&
    a.confidence > 0 &&
    a.evidence.length > 0
  );
}

const DAY_MS = 86400000;
/**
 * Newest evidence must be at most this recent before `block` is recommendable
 * (the same policy `FRESH_EVIDENCE_DAYS` / `freshEvidenceGate` applies to
 * model output in packages/clef). Undated evidence never counts as fresh
 * (fail-closed); a stale `block` is downgraded to `hunt` where behavioural
 * evidence exists, or `monitor`, with reason code `FRESH_EVIDENCE_REQUIRED`.
 */
const FRESH_EVIDENCE_DAYS = 14;

function applyFreshEvidenceGate(
  actions: Assessment["recommended_actions"],
  a: Assessment,
): Assessment["recommended_actions"] {
  const last = freshness(a.evidence).last_observed;
  const fresh =
    last !== null &&
    Date.now() - Date.parse(last) <= FRESH_EVIDENCE_DAYS * DAY_MS;
  if (fresh) return actions;
  const downgrade: "hunt" | "monitor" = a.evidence.some((e) => e.behavioural)
    ? "hunt"
    : "monitor";
  const withCode = (
    x: Assessment["recommended_actions"][number],
  ): Assessment["recommended_actions"][number] =>
    x.reason_codes.includes("FRESH_EVIDENCE_REQUIRED")
      ? x
      : { ...x, reason_codes: [...x.reason_codes, "FRESH_EVIDENCE_REQUIRED"] };
  const merged: Assessment["recommended_actions"] = [];
  for (const x of actions.map((y) =>
    withCode(y.action === "block" ? { ...y, action: downgrade } : y),
  )) {
    const existing = merged.find((y) => y.action === x.action);
    if (!existing) merged.push(x);
    else
      existing.reason_codes = [
        ...new Set([...existing.reason_codes, ...x.reason_codes]),
      ];
  }
  return merged;
}

/**
 * Recommended actions derived from the effective decision — never left over
 * from a stale model output or an earlier analyst step:
 *
 * - an analyst benign decision never recommends blocking or investigation
 *   (monitor when the customer observed the indicator, ignore otherwise);
 * - anything still awaiting analyst review is investigated, or enriched when
 *   there is no evidence at all to review;
 * - a settled malicious decision recommends block/hunt per evidence (block
 *   only with supporting evidence, and only while that evidence is fresh);
 * - a settled suspicious decision recommends hunt/monitor;
 * - a settled unknown decision is enriched or investigated.
 */
export function effectiveRecommendations(
  a: Assessment,
): Assessment["recommended_actions"] {
  const decision = effectiveDecision(a);
  const awaitingReview =
    a.status !== "confirmed" && (a.human_review || a.status !== "pending");
  const recommend = (
    action: Assessment["recommended_actions"][number]["action"],
  ): Assessment["recommended_actions"][number] => ({
    action,
    confidence: a.confidence,
    reason_codes: a.reason_codes,
  });
  const investigateOrEnrich = () => [
    recommend(a.evidence.length > 0 ? "investigate" : "enrich"),
  ];
  if (
    decision.classification === "benign" &&
    (decision.source === "analyst" || !awaitingReview)
  )
    return [recommend(a.customer.observed ? "monitor" : "ignore")];
  if (awaitingReview) return investigateOrEnrich();
  if (decision.classification === "malicious") {
    if (a.evidence.length === 0) return [recommend("hunt")];
    return applyFreshEvidenceGate(
      [recommend("block"), recommend("hunt")],
      a,
    );
  }
  if (decision.classification === "suspicious")
    return [recommend("hunt"), recommend("monitor")];
  return investigateOrEnrich();
}
