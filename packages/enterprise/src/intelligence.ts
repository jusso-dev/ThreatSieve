import type { Dossier } from "./types";
import {
  EnvironmentSchema,
  EvidenceSchema,
  type IntelEntity,
  type Evidence,
  type Assessment,
} from "../../schemas/src/index";
import type { MatchCriteria, WorkObject } from "../../schemas/src/enterprise";
import { sourceReliabilities } from "./sources";
import { OperationsRepository } from "./repository";
import { scoreDossier } from "./scoring";
export async function dossier(
  repo: OperationsRepository,
  id: string,
): Promise<Dossier> {
  if (!(await repo.intel.visible(repo.tenant, id)))
    throw new Error("Entity unavailable");
  const entity = (await repo.intel.entity(id))!;
  const [
    global,
    privateRows,
    sources,
    env,
    latest,
    relationships,
    related,
    sightings,
    events,
    provenance,
    changes,
    decisions,
    tags,
  ] = await Promise.all([
    repo.intel.evidence(id, 101, repo.tenant),
    repo.db
      .prepare(
        "SELECT data FROM customer_observations WHERE tenant_id=? AND observable_id=? ORDER BY observed_at DESC LIMIT 101",
      )
      .bind(repo.tenant, id)
      .all<{ data: string }>(),
    sourceReliabilities(repo.db, repo.tenant),
    repo.db
      .prepare("SELECT data FROM customer_environments WHERE tenant_id=?")
      .bind(repo.tenant)
      .first<{ data: string }>(),
    repo.db
      .prepare(
        "SELECT data FROM assessments WHERE tenant_id=? AND observable_id=? ORDER BY created_at DESC,id LIMIT 21",
      )
      .bind(repo.tenant, id)
      .all<{ data: string }>(),
    repo.intel.edges(id, 101, repo.tenant),
    repo.related(id),
    repo.sightings(id),
    repo.events(id),
    repo.db
      .prepare(
        "SELECT provenance FROM entity_sources WHERE entity_id=? ORDER BY source_id LIMIT 101",
      )
      .bind(id)
      .all<{ provenance: string }>(),
    repo.db
      .prepare(
        "SELECT id,event_type,reference_id,created_at FROM intelligence_changes WHERE entity_id=? AND (tenant_id IS NULL OR tenant_id=?) ORDER BY created_at DESC LIMIT 100",
      )
      .bind(id, repo.tenant)
      .all<{
        id: string;
        event_type: string;
        reference_id: string;
        created_at: string;
      }>(),
    repo.db
      .prepare(
        "SELECT f.id,f.assessment_id,f.field,f.reason,f.created_at FROM analyst_feedback f JOIN assessments a ON a.tenant_id=f.tenant_id AND a.id=f.assessment_id WHERE f.tenant_id=? AND a.observable_id=? ORDER BY f.created_at DESC LIMIT 100",
      )
      .bind(repo.tenant, id)
      .all<{
        id: string;
        assessment_id: string;
        field: string;
        reason: string;
        created_at: string;
      }>(),
    repo.db
      .prepare(
        "SELECT tag FROM entity_tags WHERE tenant_id=? AND entity_id=? ORDER BY tag LIMIT 100",
      )
      .bind(repo.tenant, id)
      .all<{ tag: string }>(),
  ]);
  const evidence = [
    ...global.slice(0, 100),
    ...privateRows.results
      .slice(0, 100)
      .map((r) => EvidenceSchema.parse(JSON.parse(r.data))),
  ];
  const assessments = latest.results
    .slice(0, 20)
    .map((r) => JSON.parse(r.data) as Assessment);
  const scores = scoreDossier(
    entity,
    evidence,
    sources,
    EnvironmentSchema.parse(env ? JSON.parse(env.data) : {}),
    assessments[0],
  );
  const timeline = [
    ...changes.results
      .filter(
        (c) => !["evidence.created", "sighting.created"].includes(c.event_type),
      )
      .map((c) => ({
        id: c.id,
        type: c.event_type,
        timestamp: c.created_at,
        title: c.event_type.replaceAll(".", " "),
        reference: {
          type:
            c.event_type === "score.changed"
              ? "assessment"
              : c.event_type === "relationship.created"
                ? "relationship"
                : "entity",
          id: c.reference_id,
        },
        description: "Recorded intelligence change",
      })),
    ...relationships.slice(0, 100).map((r) => ({
      id: r.id,
      type: "relationship",
      timestamp: r.lastSeen ?? r.updatedAt,
      title: r.relationshipType.replaceAll("_", " "),
      reference: { type: "relationship", id: r.id },
      description:
        r.provenance.sourceName + " · " + r.assertionType.replaceAll("_", " "),
    })),
    ...decisions.results.map((d) => ({
      id: d.id,
      type: "analyst.decision",
      timestamp: d.created_at,
      title: "Analyst decision: " + d.field,
      reference: { type: "assessment", id: d.assessment_id },
      description: d.reason,
    })),
    ...evidence.map((e) => ({
      id: e.id,
      type: "evidence",
      timestamp: e.observedAt ?? e.createdAt,
      title: e.provenance.sourceName,
      reference: { type: "evidence", id: e.id },
      description:
        typeof e.data.description === "string" ? e.data.description : e.type,
    })),
    ...assessments.map((a) => ({
      id: a.assessment_id,
      type: "assessment",
      timestamp: a.created_at,
      title:
        "Assessment: " +
        (a.effective_classification ?? a.malicious.classification),
      reference: { type: "assessment", id: a.assessment_id },
      description: "Confidence " + Math.round(a.confidence * 100) + "%",
    })),
    ...events.data.map((e) => ({
      id: e.id,
      type: e.event_type,
      timestamp: e.created_at,
      title: e.event_type.replaceAll(".", " "),
      reference: { type: "event", id: e.id },
      description: typeof e.data.body === "string" ? e.data.body : "",
    })),
  ].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  return {
    entity,
    workspaceTags: tags.results.map((t) => t.tag),
    evidence,
    assessments,
    relationships: relationships.slice(0, 100),
    related,
    sightings: sightings.data,
    timeline,
    scores,
    provenance: provenance.results
      .slice(0, 100)
      .map((r) => JSON.parse(r.provenance) as Record<string, unknown>),
    truncated:
      global.length > 100 ||
      privateRows.results.length > 100 ||
      relationships.length > 100 ||
      latest.results.length > 20 ||
      events.truncated ||
      Boolean(sightings.next_cursor),
  };
}
export function criterionMatches(
  criteria: MatchCriteria,
  entity: IntelEntity,
  evidence: Evidence[],
) {
  evidence = evidence.filter(
    (e) =>
      e.confidence >= criteria.minConfidence &&
      (!criteria.from || (e.observedAt ?? e.createdAt) >= criteria.from) &&
      (!criteria.to || (e.observedAt ?? e.createdAt) <= criteria.to),
  );
  const dimensions: {
    name: string;
    matched: boolean;
    evidenceIds: string[];
  }[] = [];
  const add = (
    name: string,
    configured: unknown[],
    predicate: (e: Evidence) => boolean,
    entityMatch = false,
  ) => {
    if (configured.length) {
      const hits = evidence.filter(predicate);
      dimensions.push({
        name,
        matched: entityMatch || hits.length > 0,
        evidenceIds: hits.map((e) => e.id),
      });
    }
  };
  const exact = (values: string[], raw: unknown): boolean => {
    const strings = (Array.isArray(raw) ? raw : [raw]).filter(
      (v): v is string => typeof v === "string",
    );
    return strings.some((v) =>
      values.some((w) => w.trim().toLowerCase() === v.trim().toLowerCase()),
    );
  };
  const words = (values: string[], raw: unknown) =>
    values.some((v) =>
      JSON.stringify(raw).toLowerCase().includes(v.toLowerCase()),
    );
  add(
    "entityTypes",
    criteria.entityTypes,
    () => false,
    criteria.entityTypes.includes(entity.type),
  );
  add(
    "keywords",
    criteria.keywords,
    (e) => words(criteria.keywords, e.data),
    words(criteria.keywords, [entity.name, entity.aliases, entity.description]),
  );
  for (const key of [
    "technologies",
    "industries",
    "countries",
    "actors",
    "techniques",
    "tags",
  ] as const) {
    const fields: Record<typeof key, string[]> = {
      technologies: ["product", "vendor", "technology", "technologies"],
      industries: ["industry", "industries", "sector", "sectors"],
      countries: ["country", "countries", "targetCountry"],
      actors: ["actorId", "actor", "actors"],
      techniques: ["techniqueId", "techniques"],
      tags: ["tags"],
    };
    add(
      key,
      criteria[key],
      (e) => fields[key].some((f) => exact(criteria[key], e.data[f] ?? "")),
      exact(criteria[key], entity.data[key] ?? []) ||
        (key === "actors" &&
          ["threat-actor", "intrusion-set"].includes(entity.type) &&
          exact(criteria[key], [entity.id, entity.name, ...entity.aliases])) ||
        (key === "techniques" &&
          entity.type === "attack-technique" &&
          exact(criteria[key], [entity.id, entity.externalId])),
    );
  }
  add("sourceIds", criteria.sourceIds, (e) =>
    criteria.sourceIds.includes(e.sourceId),
  );
  const supported = evidence.filter(
    (e) =>
      e.confidence >= criteria.minConfidence &&
      (!criteria.from || (e.observedAt ?? e.createdAt) >= criteria.from) &&
      (!criteria.to || (e.observedAt ?? e.createdAt) <= criteria.to),
  );
  const supportedIds = new Set(supported.map((e) => e.id));
  return {
    matches:
      dimensions.length > 0 &&
      dimensions.every((d) => d.matched) &&
      supported.length > 0,
    dimensions: dimensions.map((d) => ({
      ...d,
      matched: d.matched && supported.length > 0,
      evidenceIds: d.evidenceIds.filter((id) => supportedIds.has(id)),
    })),
    evidence: supported,
  };
}
/** Bounded candidates, surfaced as suggestions until analysts link them. */
export async function requirementCoverage(
  repo: OperationsRepository,
  object: WorkObject,
) {
  const explicit: Evidence[] = [];
  const entities = new Map<string, IntelEntity>();
  for (const ref of object.references.filter(
    (r) => r.relation !== "contradicts",
  )) {
    if (ref.type === "evidence") explicit.push(await repo.evidence(ref.id));
    if (ref.type === "assessment") {
      const a = await repo.intel.assessment(repo.tenant, ref.id);
      if (a) {
        explicit.push(...a.evidence);
        const e = await repo.intel.entity(a.observable.id);
        if (e) entities.set(e.id, e);
      }
    }
    if (ref.type === "entity") {
      const e = await repo.intel.entity(ref.id);
      if (e) {
        entities.set(e.id, e);
        explicit.push(...(await repo.intel.evidence(e.id, 50, repo.tenant)));
      }
    }
  }
  const evidence = [...new Map(explicit.map((e) => [e.id, e])).values()];
  for (const ev of evidence)
    if (
      ev.observableId &&
      !entities.has(ev.observableId) &&
      (await repo.intel.visible(repo.tenant, ev.observableId))
    ) {
      const e = await repo.intel.entity(ev.observableId);
      if (e) entities.set(e.id, e);
    }

  const dates = evidence
    .map((e) => Date.parse(e.observedAt ?? e.createdAt))
    .filter(Number.isFinite);
  const criteria = "criteria" in object ? object.criteria : null;
  const dimensions = criteria
    ? [
        ...new Set(
          [...entities.values()].flatMap((e) =>
            criterionMatches(
              criteria,
              e,
              evidence.filter(
                (ev) => !ev.observableId || ev.observableId === e.id,
              ),
            ).dimensions.map((d) => d.name),
          ),
        ),
      ]
    : [];
  const configured = criteria
    ? Object.entries(criteria)
        .filter(
          ([key, v]) => Array.isArray(v) && v.length && key !== "entityTypes",
        )
        .map(([key]) => key)
    : [];
  if (criteria?.entityTypes.length) configured.push("entityTypes");
  const satisfied = new Set<string>();
  if (criteria)
    for (const e of entities.values())
      for (const d of criterionMatches(
        criteria,
        e,
        evidence.filter((ev) => !ev.observableId || ev.observableId === e.id),
      ).dimensions)
        if (d.matched) satisfied.add(d.name);
  const gapCodes = configured
    .filter((k) => !satisfied.has(k))
    .map((k) => ({
      code: "MISSING_" + k.toUpperCase(),
      message:
        "No linked evidence supports the " + k + " collection criterion.",
    }));
  if (!evidence.length)
    gapCodes.unshift({
      code: "NO_SUPPORT",
      message: "No evidence has been linked to this requirement.",
    });
  if (!configured.length)
    gapCodes.push({
      code: "CRITERIA_UNDEFINED",
      message: "Define collection criteria before measuring coverage.",
    });
  const newest = dates.length ? Math.max(...dates) : null;
  if (newest && Date.now() - newest > 30 * 86400000)
    gapCodes.push({
      code: "STALE_SUPPORT",
      message: "Supporting intelligence is older than 30 days.",
    });
  const weights = await sourceReliabilities(repo.db, repo.tenant);
  const confidence = evidence.length
    ? evidence.reduce(
        (s, e) =>
          s +
          e.confidence *
            (weights.find((w) => w.id === e.sourceId)?.reliability ?? 0.5),
        0,
      ) / evidence.length
    : null;
  return {
    coverage: configured.length
      ? Math.round((satisfied.size / configured.length) * 100)
      : null,
    coverageLabel:
      "Configured criteria with linked support; not an answer-completeness score",
    criteria: configured.map((name) => ({
      name,
      satisfied: satisfied.has(name),
    })),
    freshness: newest ? new Date(newest).toISOString() : null,
    confidence,
    evidenceCount: evidence.length,
    newEvidence:
      object.kind === "requirement" && object.lastReviewed
        ? evidence.filter((e) => e.createdAt > object.lastReviewed!).length
        : evidence.length,
    gaps: [
      ...gapCodes,
      ...(object.kind === "requirement"
        ? object.gaps.map((message) => ({ code: "ANALYST_GAP", message }))
        : []),
    ],
    dimensions,
  };
}

export async function cachedCoverage(
  repo: OperationsRepository,
  object: WorkObject,
) {
  const row = await repo.db
    .prepare(
      "SELECT data FROM requirement_metrics WHERE tenant_id=? AND requirement_id=? AND revision=? AND updated_at>?",
    )
    .bind(
      repo.tenant,
      object.id,
      object.revision,
      new Date(Date.now() - 300000).toISOString(),
    )
    .first<{ data: string }>();
  if (row)
    return JSON.parse(row.data) as Awaited<
      ReturnType<typeof requirementCoverage>
    >;
  const metrics = await requirementCoverage(repo, object);
  await repo.db
    .prepare(
      "INSERT INTO requirement_metrics VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,requirement_id) DO UPDATE SET revision=excluded.revision,data=excluded.data,updated_at=excluded.updated_at",
    )
    .bind(
      repo.tenant,
      object.id,
      object.revision,
      JSON.stringify(metrics),
      new Date().toISOString(),
    )
    .run();
  return metrics;
}
