import type { ReasonCode } from "../../schemas/src/index";

/** Evidence older than this is stale (activity "stale"). */
export const STALE_AFTER_DAYS = 30;
/** Evidence older than this is expired (activity "expired"). */
export const EXPIRES_AFTER_DAYS = 90;

const DAY_MS = 86400000;

/**
 * The freshness of an indicator, derived from evidence observation times only.
 *
 * Vocabulary: `last_observed` is an OBSERVATION time — the newest evidence
 * `observedAt` — never a retrieval or processing timestamp and never wall
 * clock. When evidence carries no observation dates the activity is
 * `unknown` (fail-closed: undated evidence is never presented as "active").
 */
export interface FreshnessState {
  first_observed: string | null;
  last_observed: string | null; // max evidence observedAt — an OBSERVATION time, never processing time
  valid_until: string | null;
  activity: "active" | "stale" | "expired" | "unknown";
  stale: boolean;
  stale_reasons: string[]; // SCREAMING_SNAKE e.g. EVIDENCE_OLDER_THAN_30D, SOURCE_STATUS_OFFLINE_AT_COLLECTION
}

function observedTime(observedAt?: string): number | null {
  if (!observedAt) return null;
  const t = Date.parse(observedAt);
  return Number.isNaN(t) ? null : t;
}

/**
 * Source-reported status at collection time (e.g. the Feodo normalisation in
 * `additional-feeds.ts` stores `data.status` from the feed record). A record
 * whose source said the infrastructure was offline is a historical
 * association only — it can never yield `activity: "active"`.
 */
function offlineAtCollection(
  data: Record<string, unknown> | undefined,
): boolean {
  if (!data) return false;
  return ["status", "url_status", "source_status"].some((field) => {
    const value = data[field];
    return (
      typeof value === "string" && value.trim().toLowerCase() === "offline"
    );
  });
}

/**
 * The one freshness policy. `now` is an ISO reference time (defaults to the
 * current instant); it is used only to measure evidence age, never recorded
 * as an observation.
 *
 * Policy defaults: `stale` when the newest evidence `observedAt` is more than
 * 30 days old, `expired` past 90 days, `unknown` when no evidence dates
 * exist. `valid_until` = newest observedAt + 90 days. Evidence whose source
 * status was offline at collection, or which carries no observation date, can
 * never yield `activity: "active"`.
 */
export function freshness(
  evidence: { observedAt?: string; data?: Record<string, unknown> }[],
  now?: string,
): FreshnessState {
  const reference = Date.parse(now ?? new Date().toISOString());
  const nowMs = Number.isNaN(reference) ? Date.now() : reference;
  const observations = evidence
    .map((e) => observedTime(e.observedAt))
    .filter((t): t is number => t !== null && t <= nowMs);
  const firstMs = observations.length
    ? observations.reduce((first, time) => Math.min(first, time))
    : null;
  const lastMs = observations.length
    ? observations.reduce((last, time) => Math.max(last, time))
    : null;
  // Observation times, normalised to ISO — never `now`, never processing time.
  const first_observed =
    firstMs === null ? null : new Date(firstMs).toISOString();
  const last_observed = lastMs === null ? null : new Date(lastMs).toISOString();
  const valid_until =
    lastMs === null
      ? null
      : new Date(lastMs + EXPIRES_AFTER_DAYS * DAY_MS).toISOString();

  const offline = evidence.some((e) => offlineAtCollection(e.data));
  const undated = evidence.some((e) => observedTime(e.observedAt) === null);
  const future = evidence.some((e) => {
    const time = observedTime(e.observedAt);
    return time !== null && time > nowMs;
  });

  const stale_reasons: string[] = [];
  if (lastMs === null) {
    stale_reasons.push("NO_OBSERVATION_DATES");
  } else {
    const age = nowMs - lastMs;
    if (age > STALE_AFTER_DAYS * DAY_MS)
      stale_reasons.push("EVIDENCE_OLDER_THAN_30D");
    if (age > EXPIRES_AFTER_DAYS * DAY_MS)
      stale_reasons.push("EVIDENCE_OLDER_THAN_90D");
    if (undated) stale_reasons.push("EVIDENCE_WITHOUT_OBSERVATION_DATE");
  }
  if (offline) stale_reasons.push("SOURCE_STATUS_OFFLINE_AT_COLLECTION");
  if (future) stale_reasons.push("FUTURE_OBSERVATION_DATE");

  let activity: FreshnessState["activity"] = "unknown";
  if (lastMs !== null) {
    const age = nowMs - lastMs;
    activity =
      age > EXPIRES_AFTER_DAYS * DAY_MS
        ? "expired"
        : age > STALE_AFTER_DAYS * DAY_MS
          ? "stale"
          : "active";
    // Fail-closed: a source-reported-offline record, or evidence without an
    // observation date, means freshness is not demonstrated — never "active".
    if (activity === "active" && (offline || undated || future))
      activity = "stale";
  }

  return {
    first_observed,
    last_observed,
    valid_until,
    activity,
    stale: activity !== "active",
    stale_reasons,
  };
}

/**
 * Reassessment trigger: an expired indicator needs fresh evidence before it
 * is treated as a current threat again. The historical malicious association
 * is retained — it is flagged `HISTORICAL_ASSOCIATION_ONLY`, not discarded.
 */
export function reassessmentTrigger(state: FreshnessState): {
  trigger: boolean;
  reason_codes: ReasonCode[];
} {
  const reason_codes: ReasonCode[] = [];
  if (state.activity === "expired") reason_codes.push("EXPIRED_INDICATOR");
  if (state.activity !== "active" && state.last_observed !== null)
    reason_codes.push("HISTORICAL_ASSOCIATION_ONLY");
  return { trigger: state.activity === "expired", reason_codes };
}
