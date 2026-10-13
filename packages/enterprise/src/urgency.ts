import type { Assessment } from "../../schemas/src/index";
import { freshness } from "../../intel/src/freshness";

/**
 * Operational urgency (audit finding 5, P1): the ordering key of the ACTIONABLE
 * queue. It separates four questions that the priority queue used to conflate:
 *
 * - threat severity    — how bad is the thing (dossier threat dimension);
 * - evidence confidence — how well supported is that claim;
 * - customer relevance — does it touch this workspace;
 * - operational urgency — how urgently must operations respond RIGHT NOW
 *   (this module: asset impact, exposure, freshness, exploitation, evidence
 *   confidence and review state).
 *
 * "Insufficient evidence" is UNKNOWN, never low. A zero-evidence assessment is
 * not a low-threat assessment — it is an unrankable one. It routes to the
 * enrichment backlog (packages/database/src/repository.ts `assessmentSummary`)
 * and is never ranked in the queue; surfaces that render its values say
 * "Unknown", never 0%.
 *
 * Unknown-component policy: when an input is unknown the component contributes
 * the neutral midpoint {@link URGENCY_UNKNOWN} (0.5) to the weighted sum —
 * deliberately NOT zero, because zero would encode "low threat" for missing
 * information. Every unknown component is additionally listed in
 * `unknownComponents` so callers can render "Unknown" instead of a number.
 *
 * Queue ordering is computed in SQL (packages/database/src/assessment-query.ts
 * `urgencySql`) so keyset pagination keeps working — that is the "computable in
 * SQL" choice for this contract. This function is the same formula in
 * TypeScript: it feeds the UI cards, the tests, and
 * `encodeAssessmentCursor`. Both sides share the exported constants below and
 * round to {@link URGENCY_ROUND_DIGITS}; tests/priority-queue.test.ts asserts
 * the SQL expression and this function agree on stored rows.
 */

/** Components each 0..1; `urgency` is their weighted sum, also 0..1. */
export interface UrgencyComponents {
  assetImpact: number;
  exposure: number;
  freshness: number;
  exploitation: number;
  evidenceConfidence: number;
  reviewState: number;
}

export interface OperationalUrgency {
  /** 0..1 weighted sum of the components (rounded to URGENCY_ROUND_DIGITS). */
  urgency: number;
  components: UrgencyComponents;
  /**
   * Additive to the pinned shape: components whose input was unknown. Their
   * value is the neutral midpoint (never 0 — unknown is not low), so callers
   * can distinguish "neutral because unknown" from "actually mid-scale".
   */
  unknownComponents: (keyof UrgencyComponents)[];
}

/**
 * Weighted sum, weights total 1. Exploitation (KEV) is the heaviest single
 * factor: actively exploited vulnerabilities outrank model sentiment — the
 * opposite of the audited failure where a 5% model probability on a synthetic
 * `.invalid` domain outranked a KEV-listed vulnerability.
 */
export const URGENCY_WEIGHTS = {
  assetImpact: 0.2,
  exposure: 0.15,
  freshness: 0.15,
  exploitation: 0.25,
  evidenceConfidence: 0.15,
  reviewState: 0.1,
} as const;

/** Neutral midpoint contributed by an unknown component. Never 0. */
export const URGENCY_UNKNOWN = 0.5;

/** Rounding for queue/cursor parity between SQL and TypeScript.
 *  Four decimals: the weighted sum of the fixed scale tables is a multiple of
 *  0.0005, which is a half-way tie at 3 decimals (SQLite and JS round ties
 *  differently) but never at 4 — so both sides quantise identically. */
export const URGENCY_ROUND_DIGITS = 4;

/** Asset impact: customer-asserted priority of the affected asset. */
export const URGENCY_PRIORITY_IMPACT = {
  critical: 1,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
} as const;

/**
 * Freshness tiers derived from FreshnessState.activity
 * (packages/intel/src/freshness.ts): active evidence demands action now,
 * stale less, expired least. `unknown` activity falls back to the neutral
 * midpoint (an undated record is unknown, not old).
 */
export const URGENCY_FRESHNESS_ACTIVITY = {
  active: 1,
  stale: 0.5,
  expired: 0.2,
} as const;

/**
 * Review state: operational readiness. A settled decision can be acted on now;
 * an item awaiting analyst judgment cannot drive an automated response; a
 * decided-but-unconfirmed item sits between.
 */
export const URGENCY_REVIEW_STATE = {
  settled: 1,
  undecided: 0.7,
  awaiting_review: 0.4,
} as const;

const clamp01 = (n: number) => Math.min(1, Math.max(0, n));

const round3 = (n: number) =>
  Math.round(n * 10 ** URGENCY_ROUND_DIGITS) / 10 ** URGENCY_ROUND_DIGITS;

/**
 * Operational urgency of one assessment. Components (each 0..1):
 *
 * - assetImpact      — 70% customer priority (critical 1 … low 0.25) + 30%
 *                      exposed-asset count (10+ at full scale). `ctx.exposedAssets`
 *                      overrides the stored count when the caller has a fresher
 *                      figure.
 * - exposure         — 50% customer relevance + 50% observed-inside-workspace.
 * - freshness        — FreshnessState.activity tiers (freshness() over the
 *                      assessment evidence): active 1, stale 0.5, expired 0.2,
 *                      unknown → neutral + flagged.
 * - exploitation     — 1 when KEV-listed (`ctx.kev`, e.g. the `vulnerabilities.kev`
 *                      read, or evidence carrying `data.kev` from the CISA KEV
 *                      feed), 0 when the caller affirmatively checked and the
 *                      item is not listed (`ctx.kev === false`), unknown when
 *                      nobody checked (never 0 — "not checked" is not "not
 *                      exploited").
 * - evidenceConfidence — the model/analyst confidence, but ONLY when evidence
 *                      records exist. Zero evidence → unknown + flagged (and
 *                      the item routes to the enrichment backlog instead of
 *                      being ranked).
 * - reviewState      — settled 1, undecided 0.7, awaiting analyst review 0.4.
 *
 * Unknown components contribute the neutral midpoint and are listed in
 * `unknownComponents`; insufficient evidence never reads as low threat.
 */
export function operationalUrgency(
  a: Assessment,
  ctx?: { kev?: boolean; exposedAssets?: number },
): OperationalUrgency {
  const unknownComponents: (keyof UrgencyComponents)[] = [];
  const known = (
    name: keyof UrgencyComponents,
    value: number | null,
  ): number => {
    if (value === null) {
      unknownComponents.push(name);
      return URGENCY_UNKNOWN;
    }
    return clamp01(value);
  };

  const exposedAssets = ctx?.exposedAssets ?? a.customer.exposedAssets;
  const assetImpact =
    0.7 * (URGENCY_PRIORITY_IMPACT[a.customer.priority] ??
      URGENCY_PRIORITY_IMPACT.low) +
    0.3 * Math.min(Math.max(exposedAssets, 0) / 10, 1);

  const exposure =
    0.5 * clamp01(a.customer.relevance) + 0.5 * (a.customer.observed ? 1 : 0);

  // Freshness comes from the one freshness policy (leaf 1.1.2 FreshnessState).
  const activity = freshness(a.evidence).activity;
  const freshnessValue =
    activity === "unknown"
      ? known("freshness", null)
      : known("freshness", URGENCY_FRESHNESS_ACTIVITY[activity]);

  const evidenceKev = a.evidence.some((e) => e.data.kev === true);
  const exploitation = known(
    "exploitation",
    ctx?.kev === true || evidenceKev
      ? 1
      : ctx?.kev === false
        ? 0
        : null, // nobody checked: unknown, never "not exploited"
  );

  const evidenceConfidence = known(
    "evidenceConfidence",
    a.evidence.length > 0 ? clamp01(a.confidence) : null,
  );

  const reviewState =
    a.status === "confirmed"
      ? URGENCY_REVIEW_STATE.settled
      : a.human_review || a.status === "needs-investigation"
        ? URGENCY_REVIEW_STATE.awaiting_review
        : URGENCY_REVIEW_STATE.undecided;

  const components: UrgencyComponents = {
    assetImpact,
    exposure,
    freshness: freshnessValue,
    exploitation,
    evidenceConfidence,
    reviewState,
  };

  // Weighted sum; unknowns already contribute URGENCY_UNKNOWN. Same term
  // order as urgencySql in assessment-query.ts for parity.
  const urgency = round3(
    URGENCY_WEIGHTS.assetImpact * components.assetImpact +
      URGENCY_WEIGHTS.exposure * components.exposure +
      URGENCY_WEIGHTS.freshness * components.freshness +
      URGENCY_WEIGHTS.exploitation * components.exploitation +
      URGENCY_WEIGHTS.evidenceConfidence * components.evidenceConfidence +
      URGENCY_WEIGHTS.reviewState * components.reviewState,
  );

  return { urgency, components, unknownComponents };
}
