import { z } from "zod";
import type { PipelineJob, Principal } from "../../schemas/src/index";
import { canonicalJson, digest } from "../../intel/src/normalise";
import { log } from "../../observability/src/index";
import type { Mapped } from "./formats/common";
import type { IngestRequest } from "./formats/index";
import { itemId, normaliseItem, sourceKey } from "./normalise";
import {
  INGEST_INLINE_RAW_BYTES,
  type IngestFormat,
  type ItemIssue,
  type Normalisation,
  type NormalisedItem,
} from "./schema";

export interface IngestEnv {
  DB: D1Database;
  ARCHIVE: R2Bucket;
}
export interface PreparedItem {
  index: number;
  id: string;
  source_ref?: string;
  item: NormalisedItem;
  normalisation: Normalisation;
  raw: unknown;
  content_hash: string;
}
export interface RejectedItem {
  index: number;
  document: number;
  source_ref?: string;
  external_id?: string;
  issues: ItemIssue[];
}
export type Outcome = "created" | "updated" | "unchanged";
export interface Counts {
  received: number;
  accepted: number;
  rejected: number;
  deduplicated: number;
  created: number;
  updated: number;
}

/** Validates and normalises mapped items; one bad item never rejects the rest. */
export async function prepareItems(
  tenantId: string,
  request: IngestRequest,
  mapped: (Mapped & { document: number })[],
  allowedSources?: string[],
) {
  const accepted = new Map<string, PreparedItem>();
  const rejected: RejectedItem[] = [];
  const superseded: { index: number; id: string; superseded_by: number }[] = [];
  for (const [index, m] of mapped.entries()) {
    if (m.issues) {
      rejected.push({
        index,
        document: m.document,
        source_ref: m.source_ref,
        issues: m.issues,
      });
      continue;
    }
    const result = await normaliseItem(m.item, {
      format: request.format,
      defaultTlp: request.defaultTlp,
      allowedSources,
      warnings: m.warnings,
    });
    if (!result.ok) {
      rejected.push({
        index,
        document: m.document,
        source_ref: m.source_ref,
        external_id: result.external_id,
        issues: result.issues,
      });
      continue;
    }
    const id = await itemId(
      tenantId,
      result.item.source.name,
      result.item.external_id,
    );
    const previous = accepted.get(id);
    // A later copy of the same item in one request wins.
    if (previous) {
      superseded.push({ index: previous.index, id, superseded_by: index });
      accepted.delete(id);
    }
    accepted.set(id, {
      index,
      id,
      source_ref: m.source_ref,
      item: result.item,
      normalisation: result.normalisation,
      raw: result.raw,
      content_hash: await digest(
        canonicalJson({ item: result.item, raw: result.raw ?? null }),
      ),
    });
  }
  return { accepted: [...accepted.values()], rejected, superseded };
}

const UPSERT =
  "INSERT INTO ingest_items(id,tenant_id,type,format,source_key,external_id,severity,tlp,title,content_hash,data,normalisation,raw,raw_key,revision,source_updated_at,created_at,updated_at,created_by,updated_by,last_ingest_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET type=excluded.type,format=excluded.format,severity=excluded.severity,tlp=excluded.tlp,title=excluded.title,content_hash=excluded.content_hash,data=excluded.data,normalisation=excluded.normalisation,raw=excluded.raw,raw_key=excluded.raw_key,revision=ingest_items.revision+1,source_updated_at=excluded.source_updated_at,updated_at=excluded.updated_at,updated_by=excluded.updated_by,last_ingest_id=excluded.last_ingest_id WHERE ingest_items.content_hash!=excluded.content_hash AND (ingest_items.source_updated_at IS NULL OR excluded.source_updated_at IS NULL OR excluded.source_updated_at>=ingest_items.source_updated_at) RETURNING revision";

/**
 * Upserts items keyed by tenant, source and external ID. Identical content,
 * or content older than the stored `updated_at`, leaves the row unchanged.
 */
export async function storeItems(
  env: IngestEnv,
  tenantId: string,
  actor: string,
  ingestId: string,
  items: PreparedItem[],
) {
  const outcomes: {
    index: number;
    id: string;
    outcome: Outcome;
    revision?: number;
  }[] = [];
  for (let offset = 0; offset < items.length; offset += 50) {
    const chunk = items.slice(offset, offset + 50);
    const now = new Date().toISOString();
    const rawKeys: (string | null)[] = [];
    const statements: D1PreparedStatement[] = [];
    for (const p of chunk) {
      const raw = p.raw === undefined ? null : JSON.stringify(p.raw);
      let rawKey: string | null = null;
      if (raw !== null && raw.length > INGEST_INLINE_RAW_BYTES) {
        rawKey =
          "ingest/raw/" +
          tenantId +
          "/" +
          p.id +
          "/" +
          p.content_hash +
          ".json";
        await env.ARCHIVE.put(rawKey, raw);
      }
      rawKeys.push(rawKey);
      statements.push(
        env.DB.prepare(UPSERT).bind(
          p.id,
          tenantId,
          p.item.type,
          p.item.format,
          sourceKey(p.item.source.name),
          p.item.external_id,
          p.item.severity,
          p.item.tlp,
          p.item.title,
          p.content_hash,
          JSON.stringify(p.item),
          JSON.stringify(p.normalisation),
          rawKey ? null : raw,
          rawKey,
          p.item.updated_at ?? p.item.published_at,
          now,
          now,
          actor,
          actor,
          ingestId,
        ),
      );
    }
    const results = await env.DB.batch<{ revision: number }>(statements);
    for (const [i, p] of chunk.entries()) {
      const revision = results[i]?.results[0]?.revision;
      const outcome: Outcome =
        revision === undefined
          ? "unchanged"
          : revision === 1
            ? "created"
            : "updated";
      // An unapplied update must not leave its copy of the original behind.
      if (outcome === "unchanged" && rawKeys[i]) {
        const stored = await env.DB.prepare(
          "SELECT raw_key FROM ingest_items WHERE tenant_id=? AND id=?",
        )
          .bind(tenantId, p.id)
          .first<string | null>("raw_key");
        if (stored !== rawKeys[i]) await env.ARCHIVE.delete(rawKeys[i]!);
      }
      outcomes.push({
        index: p.index,
        id: p.id,
        outcome,
        ...(revision ? { revision } : {}),
      });
    }
  }
  return outcomes;
}

export function tally(outcomes: { outcome: Outcome }[]) {
  const n = (o: Outcome) => outcomes.filter((x) => x.outcome === o).length;
  return {
    created: n("created"),
    updated: n("updated"),
    unchanged: n("unchanged"),
  };
}

export function metricsStatement(
  db: D1Database,
  tenantId: string,
  counts: Partial<Counts>,
) {
  return db
    .prepare(
      "INSERT INTO ingest_metrics(tenant_id,day,received,accepted,rejected,deduplicated,created,updated) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,day) DO UPDATE SET received=received+excluded.received,accepted=accepted+excluded.accepted,rejected=rejected+excluded.rejected,deduplicated=deduplicated+excluded.deduplicated,created=created+excluded.created,updated=updated+excluded.updated",
    )
    .bind(
      tenantId,
      new Date().toISOString().slice(0, 10),
      counts.received ?? 0,
      counts.accepted ?? 0,
      counts.rejected ?? 0,
      counts.deduplicated ?? 0,
      counts.created ?? 0,
      counts.updated ?? 0,
    );
}

export function auditStatement(
  db: D1Database,
  p: Principal,
  action: string,
  entityId: string,
  correlationId: string,
  data: unknown,
  ip?: string,
) {
  return db
    .prepare("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)")
    .bind(
      crypto.randomUUID(),
      p.tenantId,
      p.userId,
      action,
      entityId,
      ip ?? null,
      correlationId,
      JSON.stringify(data),
      new Date().toISOString(),
    );
}

export const batchArchiveKey = (tenantId: string, batchId: string) =>
  "ingest/batches/" + tenantId + "/" + batchId + ".json";
export const IngestJobPayload = z.object({
  mode: z.literal("structured-ingest"),
  batchId: z.string().startsWith("inb_"),
  key: z.string().startsWith("ingest/batches/"),
  actor: z.string(),
});

/** Queue consumer for a 202 batch: stores the items archived at submission. */
export async function processIngestBatch(env: IngestEnv, job: PipelineJob) {
  const payload = IngestJobPayload.parse(job.payload);
  const tenantId = job.tenantId!;
  const object = await env.ARCHIVE.get(payload.key);
  const batch = await env.DB.prepare(
    "SELECT status,items FROM ingest_batches WHERE tenant_id=? AND id=?",
  )
    .bind(tenantId, payload.batchId)
    .first<{ status: string; items: string }>();
  if (batch?.status === "complete") return { status: "complete" };
  if (!batch || !object) throw new Error("Missing archived ingest batch");
  const items = (await object.json()) as PreparedItem[];
  const start = Date.now();
  const outcomes = await storeItems(
    env,
    tenantId,
    payload.actor,
    payload.batchId,
    items,
  );
  const counts = tally(outcomes);
  const completedAt = new Date().toISOString();
  const byIndex = new Map(outcomes.map((o) => [o.index, o.outcome]));
  const summary = (
    JSON.parse(batch.items) as { index: number; status: string }[]
  ).map((entry) => ({
    ...entry,
    status: byIndex.get(entry.index) ?? entry.status,
  }));
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE ingest_batches SET status='complete',created=?,updated=?,unchanged=?,items=?,completed_at=? WHERE tenant_id=? AND id=? AND status='queued'",
    ).bind(
      counts.created,
      counts.updated,
      counts.unchanged,
      JSON.stringify(summary),
      completedAt,
      tenantId,
      payload.batchId,
    ),
    // Counted once, by whichever delivery completes the batch.
    env.DB.prepare(
      "INSERT INTO ingest_metrics(tenant_id,day,deduplicated,created,updated) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM ingest_batches WHERE tenant_id=? AND id=? AND completed_at=?) ON CONFLICT(tenant_id,day) DO UPDATE SET deduplicated=deduplicated+excluded.deduplicated,created=created+excluded.created,updated=updated+excluded.updated",
    ).bind(
      tenantId,
      completedAt.slice(0, 10),
      counts.updated + counts.unchanged,
      counts.created,
      counts.updated,
      tenantId,
      payload.batchId,
      completedAt,
    ),
  ]);
  await env.ARCHIVE.delete(payload.key);
  log({
    tenant_id: tenantId,
    job_id: job.jobId,
    correlation_id: job.correlationId,
    stage: "ingest",
    result: "stored",
    duration_ms: Date.now() - start,
    items_created: counts.created,
    items_updated: counts.updated,
    items_deduplicated: counts.updated + counts.unchanged,
  });
  return { status: "complete", ...counts };
}

/** Tenant-scoped read. No other tenant can see an item, whatever its TLP. */
export async function getItem(env: IngestEnv, tenantId: string, id: string) {
  const row = await env.DB.prepare(
    "SELECT id,tenant_id,format,tlp,data,normalisation,raw,raw_key,revision,created_at,updated_at,last_ingest_id FROM ingest_items WHERE tenant_id=? AND id=?",
  )
    .bind(tenantId, id)
    .first<{
      id: string;
      tenant_id: string;
      format: IngestFormat;
      tlp: string;
      data: string;
      normalisation: string;
      raw: string | null;
      raw_key: string | null;
      revision: number;
      created_at: string;
      updated_at: string;
      last_ingest_id: string;
    }>();
  if (!row || !visibleTo(row, tenantId)) return null;
  let raw: unknown = row.raw === null ? null : JSON.parse(row.raw);
  if (row.raw_key)
    raw = (await (await env.ARCHIVE.get(row.raw_key))?.json()) ?? null;
  return {
    id: row.id,
    kind: "item",
    revision: row.revision,
    received_at: row.created_at,
    stored_at: row.updated_at,
    last_ingest_id: row.last_ingest_id,
    item: JSON.parse(row.data) as NormalisedItem,
    normalisation: JSON.parse(row.normalisation) as Normalisation,
    raw,
  };
}
/**
 * TLP:AMBER, AMBER+STRICT and RED items are only ever visible to the tenant
 * that submitted them. Lower markings are held to the same rule because no
 * cross-tenant sharing of ingested items exists yet.
 */
export function visibleTo(
  item: { tenant_id: string; tlp: string },
  tenantId: string,
) {
  return item.tenant_id === tenantId;
}

export async function getBatch(db: D1Database, tenantId: string, id: string) {
  const row = await db
    .prepare(
      "SELECT b.*,j.status AS job_status FROM ingest_batches b LEFT JOIN pipeline_jobs j ON j.id=b.job_id WHERE b.tenant_id=? AND b.id=?",
    )
    .bind(tenantId, id)
    .first<
      Record<string, unknown> & {
        items: string;
        errors: string;
        job_status: string | null;
      }
    >();
  if (!row) return null;
  return {
    id: row.id,
    kind: "batch",
    status:
      row.status === "complete"
        ? "complete"
        : row.job_status === "failed"
          ? "failed"
          : "queued",
    format: row.format,
    received: row.received,
    accepted: row.accepted,
    rejected: row.rejected,
    deduplicated:
      Number(row.superseded) + Number(row.updated) + Number(row.unchanged),
    superseded: row.superseded,
    created: row.created,
    updated: row.updated,
    unchanged: row.unchanged,
    items: JSON.parse(row.items) as unknown[],
    errors: JSON.parse(row.errors) as unknown[],
    created_at: row.created_at,
    completed_at: row.completed_at,
  };
}
