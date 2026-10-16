import type {
  NormalizedIntelRecord,
  PipelineJob,
} from "../../schemas/src/index";
import { RecordSchema } from "../../schemas/src/index";
import { Repository } from "../../database/src/repository";
import { canonicalJson, digest, normalise } from "./normalise";
import { ingestRecord } from "./ingest";
import { makeJob } from "../../../workers/ingest/pipeline";

const materialProvenance = (p: NormalizedIntelRecord["provenance"]) => ({
  ...p,
  retrievedAt: undefined,
});
/** Processing clocks and archive pointers do not change intelligence content.
 * Observation dates, confidence, restrictions and source identity do. */
export async function materialVersion(record: NormalizedIntelRecord) {
  return digest(
    canonicalJson({
      ...record,
      provenance: materialProvenance(record.provenance),
      entity: record.entity && {
        ...record.entity,
        provenance: materialProvenance(record.entity.provenance),
      },
      evidence: record.evidence.map((e) => ({
        ...e,
        createdAt: undefined,
        rawKey: undefined,
        provenance: materialProvenance(e.provenance),
      })),
      relationships: record.relationships.map((r) => ({
        ...r,
        createdAt: undefined,
        updatedAt: undefined,
        provenance: materialProvenance(r.provenance),
      })),
    }),
  );
}

/** Persist content, its material version and downstream delivery atomically. */
export async function ingestVersionedRecord(
  db: D1Database,
  input: NormalizedIntelRecord,
  job: PipelineJob,
  rawKey: string,
) {
  if (job.tenantId)
    throw new Error("Versioned ingestion requires a public feed");
  const record = RecordSchema.parse(input);
  const entityId = record.observable
    ? (await normalise(record.observable.value, record.observable.type)).id
    : record.entity?.id;
  const recordKey = await digest(
    canonicalJson([
      record.provenance.sourceRecordNamespace ?? record.provenance.sourceId,
      record.provenance.sourceRecordId ?? entityId,
      record.entity?.type ?? "observable",
      entityId,
      entityId ? [] : record.relationships.map((r) => r.id).sort(),
    ]),
  );
  const version = await materialVersion(record);
  const source = record.provenance.sourceId;
  type Version = {
    material_version: string;
    collected_at: string;
    entity_id: string | null;
  };
  const current = () =>
    db
      .prepare(
        "SELECT material_version,collected_at,entity_id FROM feed_record_versions WHERE source_id=? AND record_key=?",
      )
      .bind(source, recordKey)
      .first<Version>();
  const previous = await current();
  if (previous && previous.collected_at > job.createdAt)
    return { id: previous?.entity_id ?? entityId, changed: false };
  if (previous?.material_version === version) {
    // A later unchanged snapshot still advances the observation ordering fence.
    // Preserve collection provenance without replacing evidence or emitting work.
    await db.batch([
      db
        .prepare(
          "UPDATE feed_record_versions SET collected_at=? WHERE source_id=? AND record_key=? AND material_version=? AND collected_at<=? AND EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND tenant_id IS NULL AND stage='normalise' AND status IN ('queued','running') AND result IS NULL AND COALESCE(json_extract(data,'$.generation'),0)=?)",
        )
        .bind(
          job.createdAt,
          source,
          recordKey,
          version,
          job.createdAt,
          job.jobId,
          job.generation ?? 0,
        ),
      db
        .prepare(
          "UPDATE entity_sources SET provenance=? WHERE entity_id=? AND source_id=? AND source_record_id=? AND record_namespace=? AND EXISTS(SELECT 1 FROM feed_record_versions WHERE source_id=? AND record_key=? AND material_version=? AND collected_at=?) AND EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND tenant_id IS NULL AND stage='normalise' AND status IN ('queued','running') AND result IS NULL AND COALESCE(json_extract(data,'$.generation'),0)=?)",
        )
        .bind(
          JSON.stringify(record.provenance),
          previous.entity_id ?? entityId ?? "",
          source,
          record.provenance.sourceRecordId ?? entityId ?? "",
          record.provenance.sourceRecordNamespace ?? source,
          source,
          recordKey,
          version,
          job.createdAt,
          job.jobId,
          job.generation ?? 0,
        ),
    ]);
    return { id: previous?.entity_id ?? entityId, changed: false };
  }
  const writes: D1PreparedStatement[] = [];
  const repo = new Repository(db, writes);
  const id = await ingestRecord(repo, record, rawKey);
  const token = await digest(job.jobId + ":" + recordKey + ":" + version);
  const parentFence =
    "EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND tenant_id IS NULL AND stage='normalise' AND status IN ('queued','running') AND result IS NULL AND COALESCE(json_extract(data,'$.generation'),0)=?)";
  const statements = [
    db
      .prepare(
        "INSERT INTO feed_record_versions(source_id,record_key,material_version,collected_at,delivery_token,entity_id) SELECT ?,?,?,?,?,? WHERE " +
          parentFence +
          " ON CONFLICT(source_id,record_key) DO UPDATE SET material_version=excluded.material_version,collected_at=excluded.collected_at,delivery_token=excluded.delivery_token,entity_id=excluded.entity_id WHERE feed_record_versions.material_version!=excluded.material_version AND feed_record_versions.collected_at<=excluded.collected_at",
      )
      .bind(
        source,
        recordKey,
        version,
        job.createdAt,
        token,
        id ?? null,
        job.jobId,
        job.generation ?? 0,
      ),
    db
      .prepare(
        "INSERT INTO pipeline_commit_guard(token,won) SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM feed_record_versions WHERE source_id=? AND record_key=? AND delivery_token=?) AND " +
          parentFence +
          " THEN 1 ELSE 0 END",
      )
      .bind(token, source, recordKey, token, job.jobId, job.generation ?? 0),
    ...writes,
    ...(id
      ? repo.jobStatements({
          ...makeJob("enrich", id, undefined, {}, job.correlationId),
          jobId: token + ":enrich",
        })
      : []),
    db.prepare("DELETE FROM pipeline_commit_guard WHERE token=?").bind(token),
  ];
  try {
    await db.batch(statements);
  } catch (error) {
    // A concurrent delivery may win. Suppress only this transaction's deliberate
    // compare-and-swap failure; unrelated constraints remain retryable errors.
    if (
      !(error instanceof Error) ||
      !/CHECK constraint failed: won=1/.test(error.message)
    )
      throw error;
    const winner = await current();
    if (
      winner &&
      (winner.material_version === version ||
        winner.collected_at > job.createdAt)
    )
      return { id: winner?.entity_id ?? id, changed: false };
    const active = await db
      .prepare(
        "SELECT 1 FROM pipeline_jobs WHERE id=? AND tenant_id IS NULL AND stage='normalise' AND COALESCE(json_extract(data,'$.generation'),0)=? AND result IS NULL AND status IN ('queued','running')",
      )
      .bind(job.jobId, job.generation ?? 0)
      .first();
    if (active) throw error;
    return { id, changed: false };
  }
  return { id, changed: true };
}
