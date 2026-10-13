import type {
  Assessment,
  IntelEntity,
  SourceProvenance,
} from "../../schemas/src/index";
import { EntitySchema } from "../../schemas/src/index";
import type { Repository } from "./repository";
import {
  AssessmentFilters,
  EntityFilters,
} from "../../schemas/src/query";
import { AppError } from "../../observability/src/index";
import { encodeAssessmentCursor } from "./assessment-query";

export type SourceAssertion = SourceProvenance & {
  mirrored: boolean;
};

export type CanonicalEntityView = {
  entity: IntelEntity;
  canonical_id: string;
  alias_ids: string[];
  member_ids: string[];
  source_assertions: SourceAssertion[];
  source_count: number;
  mirror_count: number;
  independent_corroboration_count: number;
};

export type AssessmentSlot = Assessment & {
  assessment_count: number;
  history?: Assessment[];
};

/** Upstream key used to detect redistributed mirrors of the same record. */
function upstreamKey(p: SourceProvenance, index: number): string {
  if (p.sourceRecordId) return "record:" + p.sourceRecordId;
  return "unique:" + p.sourceId + ":" + index;
}

/**
 * Flag mirrored source assertions and compute independent corroboration.
 * Assertions that share an upstream sourceRecordId/report id form one group:
 * one primary stays mirrored:false (stable: lowest sourceId), the rest are
 * mirrored:true. Independent corroboration equals the number of non-mirrored
 * assertions — mirrors never increment it.
 */
export function annotateMirroredAssertions(
  provenances: SourceProvenance[],
): {
  assertions: SourceAssertion[];
  source_count: number;
  mirror_count: number;
  independent_corroboration_count: number;
} {
  const keys = provenances.map((p, i) => upstreamKey(p, i));
  const groups = new Map<string, number[]>();
  for (let i = 0; i < keys.length; i++) {
    const list = groups.get(keys[i]!) ?? [];
    list.push(i);
    groups.set(keys[i]!, list);
  }
  const primary = new Set<number>();
  for (const idxs of groups.values()) {
    if (idxs.length === 1) {
      primary.add(idxs[0]!);
      continue;
    }
    const sorted = [...idxs].sort((a, b) =>
      provenances[a]!.sourceId.localeCompare(provenances[b]!.sourceId),
    );
    primary.add(sorted[0]!);
  }
  const assertions: SourceAssertion[] = provenances.map((p, i) => ({
    ...p,
    mirrored: !primary.has(i),
  }));
  const mirror_count = assertions.filter((a) => a.mirrored).length;
  return {
    assertions,
    source_count: assertions.length,
    mirror_count,
    independent_corroboration_count: assertions.length - mirror_count,
  };
}

/**
 * Read-time identity group: entities that share a non-empty external_id, or
 * whose entity_sources share a non-empty source_record_id. Explicit
 * canonical_aliases rows are folded in. Peers are discovered globally, then
 * filtered to ids visible to the tenant — private peers never become
 * canonical_id, member_ids, alias_ids, or provenance sources. Canonical pick
 * among visible members = explicit alias target if visible, else lowest id.
 * Does not write alias rows.
 */
export async function identityGroup(
  repo: Repository,
  tenantId: string,
  entityId: string,
): Promise<{ canonicalId: string; memberIds: string[]; aliasIds: string[] } | null> {
  const db = repo.db;
  const explicit = await db
    .prepare(
      "SELECT canonical_id FROM canonical_aliases WHERE tenant_id=? AND alias_id=?",
    )
    .bind(tenantId, entityId)
    .first<{ canonical_id: string }>();
  const seed = explicit?.canonical_id ?? entityId;

  const discovered = new Set<string>([seed, entityId]);
  const queue = [seed, entityId];
  const seenExt = new Set<string>();
  const seenRec = new Set<string>();

  while (queue.length) {
    const id = queue.pop()!;
    const aliasRows = await db
      .prepare(
        "SELECT alias_id,canonical_id FROM canonical_aliases WHERE tenant_id=? AND (canonical_id=? OR alias_id=?)",
      )
      .bind(tenantId, id, id)
      .all<{ alias_id: string; canonical_id: string }>();
    for (const row of aliasRows.results) {
      for (const mid of [row.alias_id, row.canonical_id]) {
        if (!discovered.has(mid)) {
          discovered.add(mid);
          queue.push(mid);
        }
      }
    }
    const ent = await db
      .prepare("SELECT external_id FROM entities WHERE id=?")
      .bind(id)
      .first<{ external_id: string | null }>();
    const ext = ent?.external_id?.trim();
    if (ext && !seenExt.has(ext)) {
      seenExt.add(ext);
      const peers = await db
        .prepare(
          "SELECT id FROM entities WHERE external_id=? AND length(trim(external_id))>0",
        )
        .bind(ext)
        .all<{ id: string }>();
      for (const p of peers.results) {
        if (!discovered.has(p.id)) {
          discovered.add(p.id);
          queue.push(p.id);
        }
      }
    }
    const records = await db
      .prepare(
        "SELECT DISTINCT source_record_id AS rid FROM entity_sources WHERE entity_id=? AND length(trim(source_record_id))>0",
      )
      .bind(id)
      .all<{ rid: string }>();
    for (const { rid } of records.results) {
      if (!rid || seenRec.has(rid)) continue;
      seenRec.add(rid);
      const peers = await db
        .prepare(
          "SELECT DISTINCT entity_id AS id FROM entity_sources WHERE source_record_id=?",
        )
        .bind(rid)
        .all<{ id: string }>();
      for (const p of peers.results) {
        if (!discovered.has(p.id)) {
          discovered.add(p.id);
          queue.push(p.id);
        }
      }
    }
  }

  const memberIds: string[] = [];
  for (const mid of [...discovered].sort((a, b) => a.localeCompare(b))) {
    if (await repo.visible(tenantId, mid)) memberIds.push(mid);
  }
  if (!memberIds.length) return null;

  // Explicit canonical_aliases rows win over the lowest-id pick, but only when
  // the written canonical is visible to this tenant.
  const writtenCanonicals = new Set<string>();
  for (const mid of memberIds) {
    const row = await db
      .prepare(
        "SELECT canonical_id FROM canonical_aliases WHERE tenant_id=? AND alias_id=?",
      )
      .bind(tenantId, mid)
      .first<{ canonical_id: string }>();
    if (row && (await repo.visible(tenantId, row.canonical_id)))
      writtenCanonicals.add(row.canonical_id);
  }
  const canonicalId = writtenCanonicals.size
    ? [...writtenCanonicals].sort((a, b) => a.localeCompare(b))[0]!
    : memberIds[0]!;
  const aliasIds: string[] = [];
  for (const aid of await loadAliasIds(db, tenantId, canonicalId)) {
    if (await repo.visible(tenantId, aid)) aliasIds.push(aid);
  }
  return { canonicalId, memberIds, aliasIds };
}

export async function resolveCanonicalId(
  repo: Repository,
  tenantId: string,
  entityId: string,
): Promise<string | null> {
  const group = await identityGroup(repo, tenantId, entityId);
  return group?.canonicalId ?? null;
}

export async function aliasEntity(
  db: D1Database,
  tenantId: string,
  canonicalId: string,
  aliasId: string,
  basis: string,
): Promise<void> {
  if (canonicalId === aliasId)
    throw new AppError(
      "INVALID_ALIAS",
      400,
      "Canonical and alias entity ids must differ",
    );
  const now = new Date().toISOString();
  const [ontoAlias, alreadyAliased] = await Promise.all([
    db
      .prepare(
        "SELECT alias_id FROM canonical_aliases WHERE tenant_id=? AND alias_id=?",
      )
      .bind(tenantId, canonicalId)
      .first(),
    db
      .prepare(
        "SELECT alias_id FROM canonical_aliases WHERE tenant_id=? AND alias_id=?",
      )
      .bind(tenantId, aliasId)
      .first(),
  ]);
  if (ontoAlias)
    throw new AppError(
      "INVALID_ALIAS",
      400,
      "Canonical target is itself an alias; resolve first",
    );
  if (alreadyAliased)
    throw new AppError(
      "INVALID_ALIAS",
      409,
      "Entity is already aliased; unalias before reassigning",
    );
  await db
    .prepare(
      "INSERT INTO canonical_aliases(tenant_id,canonical_id,alias_id,basis,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(tenantId, canonicalId, aliasId, basis, now)
    .run();
}

/** Delete the alias row; separate entity views are restored (read-time grouping may still collapse). */
export async function unaliasEntity(
  db: D1Database,
  tenantId: string,
  aliasId: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      "DELETE FROM canonical_aliases WHERE tenant_id=? AND alias_id=?",
    )
    .bind(tenantId, aliasId)
    .run();
  return Boolean(result.meta.changes);
}

async function loadAliasIds(
  db: D1Database,
  tenantId: string,
  canonicalId: string,
): Promise<string[]> {
  const rows = await db
    .prepare(
      "SELECT alias_id FROM canonical_aliases WHERE tenant_id=? AND canonical_id=? ORDER BY alias_id",
    )
    .bind(tenantId, canonicalId)
    .all<{ alias_id: string }>();
  return rows.results.map((r) => r.alias_id);
}

async function loadProvenances(
  db: D1Database,
  entityIds: string[],
): Promise<SourceProvenance[]> {
  if (!entityIds.length) return [];
  const placeholders = entityIds.map(() => "?").join(",");
  const rows = await db
    .prepare(
      `SELECT provenance FROM entity_sources WHERE entity_id IN (${placeholders}) ORDER BY source_id,source_record_id`,
    )
    .bind(...entityIds)
    .all<{ provenance: string }>();
  const seen = new Set<string>();
  const out: SourceProvenance[] = [];
  for (const row of rows.results) {
    const p = JSON.parse(row.provenance) as SourceProvenance;
    const key = p.sourceId + "\0" + (p.sourceRecordId ?? "");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

/**
 * Resolve an entity id through canonical_aliases + read-time identity grouping
 * and group source assertions underneath the canonical entity. Source rows stay
 * immutable; no auto-INSERT into canonical_aliases. Returns null when the
 * requested id is not visible to the tenant.
 */
export async function canonicalEntities(
  repo: Repository,
  tenantId: string,
  entityId: string,
): Promise<CanonicalEntityView | null> {
  if (!(await repo.visible(tenantId, entityId))) return null;
  const group = await identityGroup(repo, tenantId, entityId);
  if (!group) return null;
  const entity = await repo.entity(group.canonicalId);
  if (!entity) return null;
  const provenances = await loadProvenances(repo.db, group.memberIds);
  const annotated = annotateMirroredAssertions(provenances);
  return {
    entity,
    canonical_id: group.canonicalId,
    alias_ids: group.aliasIds,
    member_ids: group.memberIds,
    source_assertions: annotated.assertions,
    source_count: annotated.source_count,
    mirror_count: annotated.mirror_count,
    independent_corroboration_count: annotated.independent_corroboration_count,
  };
}

export async function lineageSummary(
  repo: Repository,
  tenantId: string,
  entityId: string,
): Promise<{
  source_count: number;
  mirror_count: number;
  independent_corroboration_count: number;
} | null> {
  const group = await identityGroup(repo, tenantId, entityId);
  if (!group) return null;
  const provenances = await loadProvenances(repo.db, group.memberIds);
  const annotated = annotateMirroredAssertions(provenances);
  return {
    source_count: annotated.source_count,
    mirror_count: annotated.mirror_count,
    independent_corroboration_count: annotated.independent_corroboration_count,
  };
}

/**
 * Browse entities collapsed onto canonical ids (explicit aliases + read-time
 * externalId/sourceRecordId grouping). Non-canonical members are omitted.
 * Invisible peers never contribute provenance or canonical_id.
 */
export async function browseCanonicalEntities(
  repo: Repository,
  tenantId: string,
  input: Partial<EntityFilters> = {},
) {
  const filters = EntityFilters.parse(input);
  const collapsed: Array<
    IntelEntity & {
      source_count: number;
      mirror_count: number;
      independent_corroboration_count: number;
      canonical_id: string;
    }
  > = [];
  const seen = new Set<string>();
  let cursor = filters.cursor;
  let lastConsumedId: string | undefined;
  let sourceExhausted = false;
  let guard = 0;
  // Collapse can shrink a raw page below the caller's limit. Keep walking
  // browseEntities until that many canonical rows exist, or the source ends.
  while (collapsed.length < filters.limit && !sourceExhausted && guard++ < 30) {
    const page = await repo.browseEntities(tenantId, {
      ...filters,
      cursor,
      limit: 100,
    });
    if (!page.data.length) {
      sourceExhausted = true;
      break;
    }
    for (const e of page.data) {
      lastConsumedId = e.id;
      if (!(await repo.visible(tenantId, e.id))) continue;
      const group = await identityGroup(repo, tenantId, e.id);
      if (!group || seen.has(group.canonicalId)) continue;
      seen.add(group.canonicalId);
      const entity =
        group.canonicalId === e.id
          ? e
          : ((await repo.entity(group.canonicalId)) ?? e);
      const provenances = await loadProvenances(repo.db, group.memberIds);
      const annotated = annotateMirroredAssertions(provenances);
      collapsed.push({
        ...EntitySchema.parse(entity),
        source_count: annotated.source_count,
        mirror_count: annotated.mirror_count,
        independent_corroboration_count:
          annotated.independent_corroboration_count,
        canonical_id: group.canonicalId,
      });
      if (collapsed.length >= filters.limit) break;
    }
    if (collapsed.length >= filters.limit) break;
    if (!page.next_cursor) {
      sourceExhausted = true;
      break;
    }
    cursor = page.next_cursor;
  }
  const entityCursor = (id: string) =>
    btoa(encodeURIComponent(JSON.stringify({ id })));
  let next_cursor: string | null = null;
  if (collapsed.length >= filters.limit && lastConsumedId && !sourceExhausted) {
    const probe = await repo.browseEntities(tenantId, {
      ...filters,
      cursor: entityCursor(lastConsumedId),
      limit: 1,
    });
    if (probe.data.length > 0) next_cursor = entityCursor(lastConsumedId);
  }
  return { data: collapsed, next_cursor };
}

async function assessmentCounts(
  db: D1Database,
  tenantId: string,
): Promise<Map<string, number>> {
  const rows = await db
    .prepare(
      "SELECT observable_id AS oid, COUNT(*) AS cnt FROM assessments WHERE tenant_id=? GROUP BY observable_id",
    )
    .bind(tenantId)
    .all<{ oid: string; cnt: number }>();
  return new Map(rows.results.map((r) => [r.oid, r.cnt]));
}

async function latestAssessmentIds(
  db: D1Database,
  tenantId: string,
): Promise<Map<string, string>> {
  // Latest = max(created_at), tie-break max(id).
  const rows = await db
    .prepare(
      `SELECT observable_id AS oid, id FROM assessments a
       WHERE tenant_id=?
       AND id=(
         SELECT id FROM assessments
         WHERE tenant_id=a.tenant_id AND observable_id=a.observable_id
         ORDER BY created_at DESC, id DESC LIMIT 1
       )`,
    )
    .bind(tenantId)
    .all<{ oid: string; id: string }>();
  return new Map(rows.results.map((r) => [r.oid, r.id]));
}

/**
 * Latest assessment per observable, with filters/sort/cursor applied via
 * Repository.assessments (same SQL helpers as the flat list). Only rows that
 * are the latest assessment for their observable are emitted. assessment_count
 * is the full history size for that observable (not the filtered count).
 */
export async function latestAssessmentPerObservable(
  repo: Repository,
  tenantId: string,
  options: {
    limit?: number;
    includeHistory?: boolean;
    filters?: Partial<AssessmentFilters>;
    cursor?: string;
  } = {},
): Promise<{ data: AssessmentSlot[]; next_cursor: string | null }> {
  const limit = options.limit ?? 50;
  const filters = AssessmentFilters.parse(options.filters ?? {});
  const latestIds = await latestAssessmentIds(repo.db, tenantId);
  const counts = await assessmentCounts(repo.db, tenantId);
  const slots: AssessmentSlot[] = [];
  let cursor = options.cursor;
  const batchSize = Math.max(limit * 5, 50);
  let guard = 0;
  while (slots.length < limit + 1 && guard++ < 20) {
    const batch = await repo.assessments(
      tenantId,
      batchSize,
      cursor,
      filters,
    );
    if (!batch.length) break;
    for (const a of batch) {
      const latestId = latestIds.get(a.observable.id);
      if (latestId !== a.assessment_id) continue;
      if (slots.some((s) => s.observable.id === a.observable.id)) continue;
      const slot: AssessmentSlot = {
        ...a,
        assessment_count: counts.get(a.observable.id) ?? 1,
      };
      if (options.includeHistory) {
        const historyRows = await repo.db
          .prepare(
            "SELECT data FROM assessments WHERE tenant_id=? AND observable_id=? ORDER BY created_at DESC,id DESC",
          )
          .bind(tenantId, a.observable.id)
          .all<{ data: string }>();
        slot.history = historyRows.results.map(
          (r) => JSON.parse(r.data) as Assessment,
        );
      }
      slots.push(slot);
      if (slots.length >= limit + 1) break;
    }
    cursor = encodeAssessmentCursor(batch.at(-1)!, filters.sort);
    if (batch.length < batchSize) break;
  }
  const page = slots.slice(0, limit);
  const last = page.at(-1);
  return {
    data: page,
    next_cursor:
      slots.length > limit && last
        ? encodeAssessmentCursor(last, filters.sort)
        : null,
  };
}
