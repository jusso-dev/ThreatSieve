import type {
  ConfidenceFactor,
  EvidenceBundle,
  ReasonCode,
  RelevanceAssessment,
} from "../../schemas/src/index";
export interface SourceReliability {
  id: string;
  independent_group: string;
  reliability: number;
}
const clamp = (n: number) => Math.max(0, Math.min(1, n));
export function scoreConfidence(
  bundle: EvidenceBundle,
  probability: number,
  strength: number,
  sources: SourceReliability[],
  now = Date.now(),
) {
  const factors: ConfidenceFactor[] = [];
  const add = (
    code: ReasonCode,
    value: number,
    weight: number,
    ids: string[],
  ) => factors.push({ code, value, weight, evidenceIds: ids });
  const ev = bundle.evidence;
  const ids = ev.map((e) => e.id);
  const groups = new Set(
    ev.map(
      (e) =>
        sources.find((s) => s.id === e.sourceId)?.independent_group ??
        e.sourceId,
    ),
  );
  const reliability = ev.length
    ? ev.reduce(
        (sum, e) =>
          sum +
          e.confidence *
            (sources.find((s) => s.id === e.sourceId)?.reliability ?? 0.5),
        0,
      ) / ev.length
    : 0;
  // Factor codes name what each factor measures (leaf 1.2.3). The code on
  // this factor is evidence quality — mean evidence confidence weighted by
  // source reliability — NOT source multiplicity; corroboration is the
  // independent-group factor below.
  add(
    ev.length ? "EVIDENCE_RELIABILITY" : "LOW_EVIDENCE",
    reliability,
    0.35,
    ids,
  );
  // MULTI_SOURCE_CONFIRMATION only with ≥2 independent source groups; a
  // single independent group gets SINGLE_SOURCE_SUPPORT; no source at all is
  // LOW_EVIDENCE (never "confirmation").
  add(
    groups.size > 1
      ? "MULTI_SOURCE_CONFIRMATION"
      : groups.size > 0
        ? "SINGLE_SOURCE_SUPPORT"
        : "LOW_EVIDENCE",
    Math.min(groups.size / 3, 1),
    0.15,
    ids,
  );
  add("EVIDENCE_STRENGTH", strength, 0.2, ids);
  add(
    "CLASSIFIER_DECISIVENESS",
    Math.max(probability, 1 - probability),
    0.2,
    ids,
  );
  const direct = ev.filter((e) =>
    ["telemetry", "sandbox", "analyst"].includes(e.type),
  );
  add("DIRECT_EVIDENCE", direct.length ? 1 : 0, 0.1, direct.map((e) => e.id));
  const stale = ev.filter(
    (e) => e.observedAt && now - Date.parse(e.observedAt) > 30 * 86400000,
  );
  if (stale.length)
    add(
      "STALE_INTELLIGENCE",
      stale.length / Math.max(ev.length, 1),
      -0.2,
      stale.map((e) => e.id),
    );
  const conflicting =
    ev.some((e) => e.data.malicious === true) &&
    ev.some((e) => e.data.malicious === false);
  if (conflicting) add("CONFLICTING_SOURCES", 1, -0.25, ids);
  if (ev.some((e) => e.data.sharedInfrastructure === true))
    add("SHARED_INFRASTRUCTURE", 1, -0.3, ids);
  if (!ev.length) add("LOW_EVIDENCE", 1, -1, []);
  if (bundle.truncated) add("TRUNCATED_EVIDENCE", 1, -0.2, ids);
  return {
    confidence: clamp(factors.reduce((sum, f) => sum + f.value * f.weight, 0)),
    factors,
    independentSources: groups.size,
    conflicting,
  };
}
export function customerRelevance(
  bundle: EvidenceBundle,
  maliciousProbability: number,
): RelevanceAssessment {
  const { environment, observed, exposedAssets } = bundle.customerContext;
  const inventory = [
    ...environment.technologies,
    ...environment.products,
    ...environment.vendors,
  ].map((s) => s.toLowerCase());
  const technologyMatch = bundle.evidence.some((e) =>
    [e.data.product, e.data.vendor].some(
      (s) => typeof s === "string" && inventory.includes(s.toLowerCase()),
    ),
  );
  const kev = bundle.evidence.some((e) => e.data.kev === true);
  const reasons: ReasonCode[] = [];
  if (technologyMatch) reasons.push("CUSTOMER_TECH_MATCH");
  if (observed) reasons.push("CUSTOMER_OBSERVED");
  if (exposedAssets) reasons.push("CUSTOMER_ASSET_EXPOSED");
  if (kev) reasons.push("CISA_KEV");
  const relevance = clamp(
    0.2 * maliciousProbability +
      0.3 * Number(technologyMatch) +
      0.3 * Number(observed) +
      0.2 * Number(exposedAssets > 0) +
      (kev && technologyMatch ? 0.2 : 0),
  );
  return {
    relevance,
    priority:
      relevance >= 0.85
        ? "critical"
        : relevance >= 0.6
          ? "high"
          : relevance >= 0.3
            ? "medium"
            : "low",
    reasons,
    exposedAssets,
    observed,
  };
}
export function reasonCodesFor(
  bundle: EvidenceBundle,
  independentSources: number,
): ReasonCode[] {
  const codes = new Set<ReasonCode>();
  // Source-support codes follow the independent-group count, matching the
  // confidence factors: corroboration only when ≥2 independent groups.
  if (independentSources > 1) codes.add("MULTI_SOURCE_CONFIRMATION");
  else if (independentSources > 0) codes.add("SINGLE_SOURCE_SUPPORT");
  else codes.add("LOW_EVIDENCE");
  for (const e of bundle.evidence) {
    if (e.data.role === "c2") codes.add("KNOWN_C2");
    if (
      e.data.malicious === true &&
      ["sha256", "sha1", "md5"].includes(bundle.observable.type)
    )
      codes.add("KNOWN_MALWARE_HASH");
    if (e.data.role === "phishing") codes.add("KNOWN_PHISHING_URL");
    if (e.data.role === "scanning") codes.add("KNOWN_SCANNER");
    if (e.data.malicious === false) codes.add("KNOWN_BENIGN_INFRASTRUCTURE");
    if (e.data.sharedInfrastructure === true)
      codes.add("SHARED_INFRASTRUCTURE");
    if (e.data.kev === true) codes.add("CISA_KEV");
    if (e.data.malwareEntityId) codes.add("MALWARE_RELATIONSHIP");
  }
  if (!bundle.evidence.length) codes.add("LOW_EVIDENCE");
  return [...codes];
}
