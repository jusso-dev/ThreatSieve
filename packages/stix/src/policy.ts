import type {
  Assessment,
  Evidence,
  SourceProvenance,
} from "../../schemas/src/index";
import { freshness } from "../../intel/src/freshness";

/**
 * Central publication policy for STIX export.
 *
 * This module is the single publication authority: review status, permitted
 * (redistributable) evidence, derived-data rights, expiry and revocation are
 * decided here and nowhere else. `exportStix` renders what this policy
 * permits; callers cannot produce an operational bundle without going
 * through `publicationState`/`publishableClaims`.
 */
export type PublicationAudience = "research" | "operational";
export interface PublicationState {
  audience: PublicationAudience;
  eligible: boolean;
  reasons: string[]; // SCREAMING_SNAKE codes e.g. PENDING_REVIEW, STALE_EVIDENCE, NO_REDISTRIBUTABLE_EVIDENCE, LOW_CONFIDENCE, EXPIRED
  valid_until: string | null; // ISO
  revoked: boolean;
  last_observed: string | null; // max permitted evidence observedAt
  activity: "active" | "stale" | "expired" | "unknown";
}

/**
 * The freshness/expiry policy lives in `packages/intel/src/freshness.ts`
 * (leaf 1.1.2) and is re-exported here so existing importers keep working:
 * evidence older than `STALE_AFTER_DAYS` is stale (STALE_EVIDENCE), past
 * `EXPIRES_AFTER_DAYS` it is expired (EXPIRED); valid_until = last_observed +
 * 90 days.
 */
export { STALE_AFTER_DAYS, EXPIRES_AFTER_DAYS } from "../../intel/src/freshness";
/** Operational eligibility floor for assessment confidence. */
export const MIN_OPERATIONAL_CONFIDENCE = 0.5;

/** Sources whose records may be redistributed. */
export function permittedSources(a: Assessment): SourceProvenance[] {
  return a.sources.filter((s) => s.redistributable);
}

/**
 * Evidence records that may be redistributed ("permitted"): their own
 * provenance allows redistribution and their source policy allows it. This is
 * the one definition of "permitted" — the export strip filter and every
 * derived-claim rights check use it.
 */
export function permittedEvidence(a: Assessment): Evidence[] {
  const allowed = new Set(permittedSources(a).map((s) => s.sourceId));
  return a.evidence.filter(
    (e) => allowed.has(e.sourceId) && e.provenance.redistributable === true,
  );
}

/**
 * Review semantics match `packages/database/src/assessment-query.ts`: an
 * assessment is awaiting review when it is not confirmed or still flagged for
 * human review.
 */
function awaitingReview(a: Assessment): boolean {
  return a.status !== "confirmed" || a.human_review === true;
}

/**
 * Revocation: an analyst benign override after a previously malicious model
 * output revokes the indicator. The analyst decision is authoritative.
 */
function revokedByAnalyst(a: Assessment): boolean {
  const benignOverride =
    a.effective_classification === "benign" ||
    (a.analyst_decision?.field === "malicious" &&
      a.analyst_decision.value === "benign");
  return benignOverride && a.malicious.classification === "malicious";
}

/**
 * The publication verdict for one assessment, evaluated against the
 * operational publication standard (the only audience-gated standard;
 * research publication is ungated). `audience` records the standard that
 * produced `eligible`; exportStix stamps the export's own audience into the
 * embedded `x_threatsieve_publication_state` block.
 */
export function publicationState(
  a: Assessment,
  now?: string,
): PublicationState {
  const permitted = permittedEvidence(a);
  // Freshness (last_observed, valid_until, activity) is computed by the
  // shared freshness policy in packages/intel/src/freshness.ts (leaf 1.1.2)
  // from permitted evidence observation times only.
  const { last_observed, valid_until, activity } = freshness(permitted, now);

  const revoked = revokedByAnalyst(a);

  const reasons: string[] = [];
  if (awaitingReview(a)) reasons.push("PENDING_REVIEW");
  if (!permitted.length) reasons.push("NO_REDISTRIBUTABLE_EVIDENCE");
  else if (activity !== "active")
    // Freshness not demonstrated: stale (30–90d), expired (>90d) or unknown.
    reasons.push(activity === "expired" ? "EXPIRED" : "STALE_EVIDENCE");
  if (a.confidence < MIN_OPERATIONAL_CONFIDENCE) reasons.push("LOW_CONFIDENCE");
  if (revoked) reasons.push("REVOKED");

  return {
    audience: "operational",
    eligible: reasons.length === 0,
    reasons,
    valid_until,
    revoked,
    last_observed,
    activity,
  };
}

/**
 * Derived-data rights: derived claims (classification, role, attack mappings,
 * malware associations, actor associations) that assert a threat may only be
 * published when at least one supporting evidence record is permitted. When
 * the only supporting evidence is restricted, the derived claim is dropped
 * too — restricted evidence must not leak through the claims derived from it.
 * Claims asserting benignness are exempt: they suppress rather than accuse.
 * Revocation drops every threat claim, even one with permitted support.
 */
export interface PublishableClaims {
  /** The classification claim may be published (threat claims need permitted support). */
  classification: boolean;
  /** The role claim may be published (threat roles need permitted support). */
  role: boolean;
  /** techniqueId -> permitted supporting evidence ids. */
  attack: Map<string, string[]>;
  /** malwareId -> permitted supporting evidence ids. */
  malware: Map<string, string[]>;
  /** actorId -> permitted supporting evidence ids. */
  actors: Map<string, string[]>;
}

const NON_THREAT = new Set(["benign", "unknown"]);

export function publishableClaims(a: Assessment): PublishableClaims {
  const revoked = revokedByAnalyst(a);
  const permitted = permittedEvidence(a);
  const byId = new Map(permitted.map((e) => [e.id, e]));
  const classification =
    a.effective_classification ?? a.malicious.classification;
  const roleValue = a.effective_role ?? a.role.value;
  const attack = new Map<string, string[]>();
  for (const mapping of a.attack) {
    const ids = mapping.evidenceIds.filter((id) => byId.has(id));
    if (ids.length) attack.set(mapping.techniqueId, ids);
  }
  const malware = new Map<string, string[]>();
  for (const m of a.malware) {
    const ids = permitted
      .filter((e) => e.data.malwareEntityId === m.id)
      .map((e) => e.id);
    if (ids.length) malware.set(m.id, ids);
  }
  const actors = new Map<string, string[]>();
  for (const actor of a.actors) {
    const ids = actor.evidenceIds.filter((id) => byId.has(id));
    if (ids.length) actors.set(actor.id, ids);
  }
  return {
    classification:
      NON_THREAT.has(classification) ||
      (!revoked && permitted.some((e) => e.data.malicious === true)),
    role:
      NON_THREAT.has(roleValue) ||
      (!revoked &&
        permitted.some(
          (e) => typeof e.data.role === "string" && e.data.role === roleValue,
        )),
    attack: revoked ? new Map() : attack,
    malware: revoked ? new Map() : malware,
    actors: revoked ? new Map() : actors,
  };
}
