import type {
  Assessment,
  CustomerEnvironment,
  Evidence,
  IntelEntity,
} from "../../schemas/src/index";
import type { SourceReliability } from "../../scoring/src/index";
export interface ScoreFactor {
  code: string;
  label: string;
  points: number;
  evidenceIds: string[];
}
export interface Score {
  value: number | null;
  factors: ScoreFactor[];
}
const clamp = (n: number) => Math.round(Math.max(0, Math.min(100, n)));
/** Policy contributions, never a generated or concealed model score. */
export function scoreDossier(
  entity: IntelEntity,
  evidence: Evidence[],
  sources: SourceReliability[],
  environment: CustomerEnvironment,
  assessment?: Assessment | null,
  now = Date.now(),
) {
  const threat: ScoreFactor[] = [],
    confidence: ScoreFactor[] = [],
    relevance: ScoreFactor[] = [];
  const add = (
    to: ScoreFactor[],
    code: string,
    label: string,
    points: number,
    items: Evidence[] = evidence,
  ) => {
    if (points)
      to.push({ code, label, points, evidenceIds: items.map((e) => e.id) });
  };
  const malicious = evidence.filter((e) => e.data.malicious === true),
    benign = evidence.filter((e) => e.data.malicious === false);
  const groups = new Set(
    evidence.map(
      (e) =>
        sources.find((s) => s.id === e.sourceId)?.independent_group ??
        e.sourceId,
    ),
  );
  const recent = evidence.filter((e) => {
    const d = Date.parse(e.observedAt ?? e.createdAt);
    return Number.isFinite(d) && d <= now && now - d < 30 * 86400000;
  });
  const sightings = evidence.filter(
    (e) =>
      e.data.sighting === true ||
      e.type === "customer" ||
      e.type === "telemetry",
  );
  const shared = evidence.filter((e) => e.data.sharedInfrastructure === true);
  const c2 = evidence.filter(
    (e) => e.data.role === "c2" && e.data.malicious === true,
  );
  const malware = evidence.filter(
    (e) => typeof e.data.malwareEntityId === "string",
  );
  const kev = evidence.filter((e) => e.data.kev === true);
  add(
    threat,
    "MALICIOUS_SOURCE_ASSERTION",
    "Source explicitly reports malicious activity",
    malicious.length ? 25 : 0,
    malicious,
  );
  add(
    threat,
    "C2_SOURCE_ASSERTION",
    "Source reports command and control",
    c2.length ? 20 : 0,
    c2,
  );
  add(
    threat,
    "MALWARE_RELATIONSHIP",
    "Evidence names a malware relationship",
    malware.length ? 15 : 0,
    malware,
  );
  add(
    threat,
    "INDEPENDENT_CORROBORATION",
    "Multiple independent sources support maliciousness",
    new Set(
      malicious.map(
        (e) =>
          sources.find((s) => s.id === e.sourceId)?.independent_group ??
          e.sourceId,
      ),
    ).size > 1
      ? 15
      : 0,
    malicious,
  );
  add(
    threat,
    "ACTIVE_EXPLOITATION",
    "Known exploited vulnerability",
    kev.length ? 35 : 0,
    kev,
  );
  add(
    threat,
    "RECENT_MALICIOUS_OBSERVATION",
    "Recent malicious evidence",
    recent.some((e) => e.data.malicious === true) ? 10 : 0,
    recent.filter((e) => e.data.malicious === true),
  );
  add(
    threat,
    "CONFLICTING_ASSERTIONS",
    "Sources disagree about maliciousness",
    malicious.length && benign.length ? -20 : 0,
  );
  add(
    threat,
    "SHARED_INFRASTRUCTURE",
    "Shared infrastructure requires specific behavioural support",
    shared.length ? -40 : 0,
    shared,
  );
  if (assessment?.effective_classification === "malicious")
    add(
      threat,
      "ANALYST_MALICIOUS",
      "Analyst confirmed maliciousness",
      30,
      assessment.evidence,
    );
  if (assessment?.effective_classification === "benign")
    add(
      threat,
      "ANALYST_BENIGN",
      "Analyst confirmed benign classification",
      -100,
      assessment.evidence,
    );
  const reliability = evidence.length
    ? evidence.reduce(
        (sum, e) =>
          sum +
          e.confidence *
            (sources.find((s) => s.id === e.sourceId)?.reliability ?? 0.5),
        0,
      ) / evidence.length
    : 0;
  add(
    confidence,
    "SOURCE_RELIABILITY",
    "Evidence confidence weighted by source reliability",
    Math.round(reliability * 55),
  );
  add(
    confidence,
    "INDEPENDENT_SOURCES",
    "Independent source groups (maximum three)",
    Math.round(Math.min(groups.size / 3, 1) * 20),
  );
  add(
    confidence,
    "RECENCY",
    "Fraction of evidence observed within 30 days",
    evidence.length ? Math.round((recent.length / evidence.length) * 15) : 0,
    recent,
  );
  add(
    confidence,
    "DIRECT_OBSERVATION",
    "Direct tenant observations",
    sightings.length ? 10 : 0,
    sightings,
  );
  add(
    confidence,
    "CONFLICT",
    "Conflicting source assertions",
    malicious.length && benign.length ? -25 : 0,
  );
  const tech = [
    ...environment.technologies,
    ...environment.products,
    ...environment.vendors,
    ...environment.cloudProviders,
    ...environment.operatingSystems,
    ...environment.software,
    ...environment.identityProviders,
    ...environment.securityProducts,
    ...environment.exposedServices,
  ].map((s) => s.toLowerCase());
  const match = (values: string[], keys: string[]) =>
    evidence.filter((e) =>
      keys.some((key) => {
        const value = e.data[key];
        return (Array.isArray(value) ? value : [value]).some(
          (v) => typeof v === "string" && values.includes(v.toLowerCase()),
        );
      }),
    );
  const technology = match(tech, [
    "product",
    "vendor",
    "technology",
    "technologies",
  ]);
  const industry = match(
    environment.industries.map((s) => s.toLowerCase()),
    ["industry", "industries", "sector", "sectors"],
  );
  const country = match(
    environment.countries.map((s) => s.toLowerCase()),
    ["country", "countries", "targetCountry"],
  );
  add(
    relevance,
    "CUSTOMER_OBSERVED",
    "Observed inside this workspace",
    sightings.length ? 40 : 0,
    sightings,
  );
  add(
    relevance,
    "TECHNOLOGY_MATCH",
    "Exact technology or product match",
    technology.length ? 30 : 0,
    technology,
  );
  add(
    relevance,
    "INDUSTRY_MATCH",
    "Source targeting matches the organisation industry",
    industry.length ? 15 : 0,
    industry,
  );
  add(
    relevance,
    "COUNTRY_MATCH",
    "Source targeting matches a configured country",
    country.length ? 10 : 0,
    country,
  );
  add(
    relevance,
    "KEV_EXPOSURE",
    "Exploited vulnerability and technology match",
    kev.length && technology.length ? 25 : 0,
    kev,
  );
  const targeting = match(
    [
      ...environment.brands,
      ...environment.domains,
      ...environment.subsidiaries,
      ...environment.vips,
    ].map((s) => s.toLowerCase()),
    ["brand", "brands", "targetDomain", "targetOrganisation", "targetPerson"],
  );
  add(
    relevance,
    "ORGANISATION_TARGET_MATCH",
    "Source names a monitored brand, domain, subsidiary or person",
    targeting.length ? 30 : 0,
    targeting,
  );
  const critical = match(
    environment.criticalAssets.map((s) => s.toLowerCase()),
    ["asset"],
  );
  add(
    relevance,
    "CRITICAL_ASSET_OBSERVED",
    "Sighting identifies a configured critical asset",
    critical.length ? 20 : 0,
    critical,
  );
  const regions = match(
    environment.regions.map((s) => s.toLowerCase()),
    ["region", "targetRegion"],
  );
  add(
    relevance,
    "REGION_MATCH",
    "Source targeting matches a configured region",
    regions.length ? 10 : 0,
    regions,
  );
  const evaluate = (factors: ScoreFactor[], known: boolean): Score => ({
    value: known ? clamp(factors.reduce((s, f) => s + f.points, 0)) : null,
    factors,
  });
  const scores = {
    threat: evaluate(
      threat,
      Boolean(
        malicious.length ||
        benign.length ||
        kev.length ||
        assessment?.effective_classification,
      ),
    ),
    confidence: evaluate(confidence, evidence.length > 0),
    relevance: evaluate(
      relevance,
      evidence.length > 0 &&
        (tech.length > 0 ||
          environment.industries.length > 0 ||
          environment.countries.length > 0 ||
          sightings.length > 0 ||
          targeting.length > 0 ||
          regions.length > 0),
    ),
  };
  const priorityValue = Math.round(
    (scores.threat.value ?? 0) * 0.5 +
      (scores.relevance.value ?? 0) * 0.35 +
      (scores.confidence.value ?? 0) * 0.15,
  );
  const gaps = [] as { code: string; message: string }[];
  if (!evidence.length)
    gaps.push({
      code: "NO_EVIDENCE",
      message: "No supporting evidence is available.",
    });
  if (groups.size === 1)
    gaps.push({
      code: "SINGLE_SOURCE",
      message: "Only one independent source group supports this intelligence.",
    });
  if (evidence.length && !recent.length)
    gaps.push({
      code: "STALE_INTELLIGENCE",
      message: "No evidence observed within the last 30 days.",
    });
  if (
    !tech.length &&
    !environment.industries.length &&
    !environment.countries.length
  )
    gaps.push({
      code: "ENVIRONMENT_MISSING",
      message:
        "Customer technology and targeting context have not been supplied.",
    });
  if (malicious.length && benign.length)
    gaps.push({
      code: "CONFLICTING_SOURCES",
      message: "Sources disagree; an analyst must resolve the conflict.",
    });
  if (!evidence.some((e) => e.behavioural))
    gaps.push({
      code: "BEHAVIOUR_MISSING",
      message: "No behavioural evidence supports ATT&CK or actor attribution.",
    });
  return {
    policy: "dossier-v1",
    ...scores,
    priority: {
      value: priorityValue,
      label:
        priorityValue >= 80
          ? "critical"
          : priorityValue >= 60
            ? "high"
            : priorityValue >= 30
              ? "medium"
              : "low",
      formula:
        "50% threat + 35% relevance + 15% confidence; missing dimensions contribute zero, not benign evidence",
    },
    gaps,
    independentSources: groups.size,
    entityId: entity.id,
  };
}
