import {
  EntitySchema,
  EvidenceSchema,
  RelationshipSchema,
  type Evidence,
  type IntelEntity,
  type IntelRelationship,
} from "../../schemas/src/index";

/**
 * Batched, tenant-scoped reads for POST /v1/lookup. Each helper answers up to
 * a few hundred entities in one statement and applies the same visibility,
 * tenant source policy and relationship feedback rules as Repository.
 */
const ids = (values: string[]) => JSON.stringify([...new Set(values)]);

export async function visibleEntities(
  db: D1Database,
  tenantId: string,
  entityIds: string[],
): Promise<Set<string>> {
  if (!entityIds.length) return new Set();
  const rows = await db
    .prepare(
      "SELECT id FROM entities WHERE id IN (SELECT value FROM json_each(?1)) AND (public_intel=1 OR EXISTS(SELECT 1 FROM tenant_observables t WHERE t.tenant_id=?2 AND t.observable_id=entities.id))",
    )
    .bind(ids(entityIds), tenantId)
    .all<{ id: string }>();
  return new Set(rows.results.map((r) => r.id));
}

export async function evidenceFor(
  db: D1Database,
  tenantId: string,
  entityIds: string[],
  perEntity = 50,
): Promise<Map<string, Evidence[]>> {
  const result = new Map<string, Evidence[]>();
  if (!entityIds.length) return result;
  const rows = await db
    .prepare(
      `SELECT entity_id,data FROM (
         SELECT entity_id,data,ROW_NUMBER() OVER (PARTITION BY entity_id ORDER BY observed_at DESC,id) AS rn
         FROM evidence WHERE entity_id IN (SELECT value FROM json_each(?1))
         AND NOT EXISTS(SELECT 1 FROM tenant_source_policy p WHERE p.tenant_id=?2 AND p.source_id=evidence.source_id AND p.enabled=0)
       ) WHERE rn<=?3 ORDER BY entity_id,rn`,
    )
    .bind(ids(entityIds), tenantId, perEntity)
    .all<{ entity_id: string; data: string }>();
  for (const row of rows.results) {
    const list = result.get(row.entity_id) ?? [];
    list.push(EvidenceSchema.parse(JSON.parse(row.data)));
    result.set(row.entity_id, list);
  }
  return result;
}

const visibleEnd = (alias: string) =>
  `(${alias}.public_intel=1 OR EXISTS(SELECT 1 FROM tenant_observables t WHERE t.tenant_id=?2 AND t.observable_id=${alias}.id))`;
const edgeFilters = `${visibleEnd("src")} AND ${visibleEnd("dst")}
  AND COALESCE((SELECT decision FROM relationship_feedback f WHERE f.tenant_id=?2 AND f.relationship_id=r.id ORDER BY f.created_at DESC,f.id DESC LIMIT 1),'confirm')!='reject'
  AND NOT EXISTS(SELECT 1 FROM tenant_source_policy p WHERE p.tenant_id=?2 AND p.source_id=r.source_id AND p.enabled=0)`;

export async function relationshipsFor(
  db: D1Database,
  tenantId: string,
  anchorIds: string[],
  perAnchor = 25,
): Promise<Map<string, IntelRelationship[]>> {
  const result = new Map<string, IntelRelationship[]>();
  if (!anchorIds.length) return result;
  const rows = await db
    .prepare(
      `WITH anchors(id) AS (SELECT value FROM json_each(?1)),
       edges AS (
         SELECT a.id AS anchor,r.id,r.confidence,r.data FROM anchors a
           JOIN relationships r ON r.source_entity_id=a.id
           JOIN entities src ON src.id=r.source_entity_id JOIN entities dst ON dst.id=r.target_entity_id
           WHERE ${edgeFilters}
         UNION ALL
         SELECT a.id AS anchor,r.id,r.confidence,r.data FROM anchors a
           JOIN relationships r ON r.target_entity_id=a.id AND r.source_entity_id!=a.id
           JOIN entities src ON src.id=r.source_entity_id JOIN entities dst ON dst.id=r.target_entity_id
           WHERE ${edgeFilters}
       )
       SELECT anchor,data FROM (
         SELECT anchor,data,ROW_NUMBER() OVER (PARTITION BY anchor ORDER BY confidence DESC,id) AS rn FROM edges
       ) WHERE rn<=?3 ORDER BY anchor,rn`,
    )
    .bind(ids(anchorIds), tenantId, perAnchor)
    .all<{ anchor: string; data: string }>();
  for (const row of rows.results) {
    const list = result.get(row.anchor) ?? [];
    list.push(RelationshipSchema.parse(JSON.parse(row.data)));
    result.set(row.anchor, list);
  }
  return result;
}

export async function entitiesById(
  db: D1Database,
  entityIds: string[],
): Promise<Map<string, IntelEntity>> {
  if (!entityIds.length) return new Map();
  const rows = await db
    .prepare(
      "SELECT data FROM entities WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(ids(entityIds))
    .all<{ data: string }>();
  const entities = rows.results.map((r) =>
    EntitySchema.parse(JSON.parse(r.data)),
  );
  return new Map(entities.map((e) => [e.id, e]));
}

export interface SourceLicence {
  id: string;
  name: string;
  license: string | null;
  redistributable: number;
  commercial_use: number | null;
  enabled: number;
  last_sync: string | null;
}
export async function sourceLicences(db: D1Database, tenantId: string) {
  const [sources, disabled] = await db.batch([
    db.prepare(
      "SELECT id,name,license,redistributable,commercial_use,enabled,last_sync FROM sources",
    ),
    db
      .prepare(
        "SELECT source_id FROM tenant_source_policy WHERE tenant_id=? AND enabled=0",
      )
      .bind(tenantId),
  ]);
  return {
    sources: new Map(
      (sources!.results as SourceLicence[]).map((s) => [s.id, s]),
    ),
    disabled: new Set(
      (disabled!.results as { source_id: string }[]).map((r) => r.source_id),
    ),
  };
}

/**
 * Licence part of a lookup or entity `sources[]` entry. `redistributable` is
 * false when the source licence forbids it or any contributing record was
 * marked non-redistributable; `commercial_use` is null when unknown.
 */
export function licenceFields(
  id: string,
  row: SourceLicence | undefined,
  recordsRedistributable: boolean,
) {
  return {
    source_id: id,
    name: row?.name ?? id,
    license: row?.license ?? null,
    redistributable: row?.redistributable === 1 && recordsRedistributable,
    commercial_use:
      row?.commercial_use === null || row?.commercial_use === undefined
        ? null
        : row.commercial_use === 1,
  };
}

export interface EntitySourceFacts {
  source_id: string;
  redistributable: boolean;
  first_published: string | null;
  last_published: string | null;
  retrieved_at: string | null;
  /** `<retrievedAt>\u001f<sourceUrl>` of the newest record with a URL. */
  latest_url: string | null;
}
/**
 * Per entity and source, one aggregated row over its entity_sources records,
 * so the answer stays bounded by the number of sources however many records a
 * source delivered. Sources the tenant disabled are left out.
 */
export async function entitySourceFacts(
  db: D1Database,
  tenantId: string,
  entityIds: string[],
): Promise<Map<string, EntitySourceFacts[]>> {
  const result = new Map<string, EntitySourceFacts[]>();
  if (!entityIds.length) return result;
  const rows = await db
    .prepare(
      `SELECT entity_id,source_id,
         MIN(COALESCE(json_extract(provenance,'$.redistributable'),0)) AS redistributable,
         MIN(json_extract(provenance,'$.publishedAt')) AS first_published,
         MAX(json_extract(provenance,'$.publishedAt')) AS last_published,
         MAX(json_extract(provenance,'$.retrievedAt')) AS retrieved_at,
         MAX(json_extract(provenance,'$.retrievedAt')||char(31)||json_extract(provenance,'$.sourceUrl')) AS latest_url
       FROM entity_sources WHERE entity_id IN (SELECT value FROM json_each(?1))
       AND NOT EXISTS(SELECT 1 FROM tenant_source_policy p WHERE p.tenant_id=?2 AND p.source_id=entity_sources.source_id AND p.enabled=0)
       GROUP BY entity_id,source_id ORDER BY entity_id,source_id`,
    )
    .bind(ids(entityIds), tenantId)
    .all<
      Omit<EntitySourceFacts, "redistributable"> & {
        entity_id: string;
        redistributable: number;
      }
    >();
  for (const { entity_id, ...row } of rows.results) {
    const list = result.get(entity_id) ?? [];
    list.push({ ...row, redistributable: row.redistributable === 1 });
    result.set(entity_id, list);
  }
  return result;
}
