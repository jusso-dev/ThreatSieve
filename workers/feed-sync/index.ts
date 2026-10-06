import { OptionalFeed } from "../../packages/intel/src/optional-feeds";
import type { AppEnv } from "../../apps/api/src/env";
import { Repository } from "../../packages/database/src/repository";
import { AdditionalFeed } from "../../packages/intel/src/additional-feeds";
import { PublicFeed } from "../../packages/intel/src/feeds";
import { JobSchema, type PipelineJob } from "../../packages/schemas/src/index";
import { makeJob } from "../ingest/pipeline";
import { z } from "zod";
import { normalise } from "../../packages/intel/src/normalise";
import { RecordSchema } from "../../packages/schemas/src/index";
export function getFeed(env: AppEnv, id: string) {
  const names: Record<string, string> = {
    mitre: "MITRE ATT&CK",
    threatfox: "ThreatFox",
    misp: "MISP Galaxy",
    urlhaus: "URLhaus",
    feodo: "Feodo Tracker",
    "cisa-kev": "CISA KEV",
  };
  if (id === "taxii" || id === "stix" || id === "misp-feed") {
    const prefix = id === "misp-feed" ? "MISP_FEED" : id.toUpperCase();
    const config = env as unknown as Record<string, string | undefined>;
    return new OptionalFeed(
      id,
      id === "taxii"
        ? "TAXII 2.1"
        : id === "stix"
          ? "STIX 2.1 feed"
          : "MISP feed",
      new Repository(env.DB),
      {
        enabled: config[prefix + "_ENABLED"] === "true",
        endpoint: config[prefix + "_ENDPOINT"],
        allowedHost: config[prefix + "_ALLOWED_HOST"],
        apiKey: config[prefix + "_API_KEY"],
      },
    );
  }
  if (id === "otx")
    return new OptionalFeed("otx", "LevelBlue OTX", new Repository(env.DB), {
      enabled: env.OTX_ENABLED === "true" && !!env.OTX_API_KEY,
      apiKey: env.OTX_API_KEY,
    });
  if (!names[id]) throw new Error("Feed unavailable");
  const Provider = ["mitre", "threatfox"].includes(id)
    ? PublicFeed
    : AdditionalFeed;
  return new Provider(id, names[id], new Repository(env.DB), env);
}
export async function syncFeed(env: AppEnv, job: PipelineJob) {
  const repo = new Repository(env.DB);
  const feed = getFeed(env, job.entityId);
  try {
    if (job.entityId === "mitre") {
      const { syncMitreStream } = await import("./mitre-stream");
      return await syncMitreStream(env, job);
    }
    const batch = await feed.fetch((await feed.getCheckpoint()) ?? undefined);
    const date = new Date().toISOString();
    const rawKey =
      "raw/" +
      feed.id +
      "/" +
      date.slice(0, 10).replace(/-/g, "/") +
      "/" +
      job.jobId +
      ".json";
    await env.ARCHIVE.put(rawKey, JSON.stringify(batch.raw), {
      httpMetadata: { contentType: "application/json" },
    });
    const recordsKey = "raw/" + feed.id + "/batches/" + job.jobId + ".json";
    await env.ARCHIVE.put(recordsKey, JSON.stringify(batch.records));
    const fanout = {
      ...makeJob(
        "ingest",
        job.entityId,
        undefined,
        {
          mode: "feed-fanout",
          recordsKey,
          rawKey,
          offset: 0,
          total: batch.records.length,
          feedJobId: job.jobId,
          checkpoint: batch.cursor,
        },
        job.correlationId,
      ),
      jobId: job.jobId + ":fanout:0",
    };
    await repo.finish(
      job,
      {
        rawKey,
        records: batch.records.length,
        checkpoint: batch.cursor,
        more: batch.more ?? false,
      },
      fanout,
    );
    await env.DB.prepare(
      "UPDATE sources SET status='syncing',last_error=NULL WHERE id=?",
    )
      .bind(feed.id)
      .run();
  } catch (error) {
    await env.DB.prepare(
      "UPDATE sources SET status='error',errors=errors+1,last_error=? WHERE id=?",
    )
      .bind(
        error instanceof Error
          ? error.message.slice(0, 160)
          : "Feed sync failed",
        feed.id,
      )
      .run();
    throw error;
  }
}
export async function fanoutFeed(env: AppEnv, job: PipelineJob) {
  const payload = z
    .object({
      recordsKey: z.string(),
      rawKey: z.string(),
      offset: z.number().int(),
      total: z.number().int(),
      feedJobId: z.string(),
      checkpoint: z.string(),
    })
    .parse(job.payload);
  const archive = await env.ARCHIVE.get(payload.recordsKey);
  if (!archive) throw new Error("Missing feed archive");
  const records = z.array(z.unknown()).parse(await archive.json());
  const repo = new Repository(env.DB);
  const page = records.slice(payload.offset, payload.offset + 500);
  for (let i = 0; i < page.length; i += 10) {
    const offset = payload.offset + i;
    const key = payload.recordsKey.replace(".json", "/" + offset + ".json");
    await env.ARCHIVE.put(key, JSON.stringify(page.slice(i, i + 10)));
    const child = {
      ...makeJob(
        "normalise",
        job.entityId,
        undefined,
        {
          feedId: job.entityId,
          feedChunk: key,
          rawKey: payload.rawKey,
          feedJobId: payload.feedJobId,
        },
        job.correlationId,
      ),
      jobId: payload.feedJobId + ":chunk:" + offset,
    };
    await repo.enqueue(child);
  }
  const nextOffset = payload.offset + page.length;
  await repo.finish(
    job,
    { records: page.length },
    nextOffset < records.length
      ? {
          ...job,
          jobId: payload.feedJobId + ":fanout:" + nextOffset,
          payload: { ...job.payload, offset: nextOffset },
        }
      : undefined,
  );
}
export async function normalizeFeedChunk(env: AppEnv, job: PipelineJob) {
  const repo = new Repository(env.DB);
  const feed = getFeed(env, String(job.payload.feedId));
  const file = await env.ARCHIVE.get(String(job.payload.feedChunk));
  if (!file) throw new Error("Feed chunk missing");
  const items = z.array(z.unknown()).parse(await file.json());
  const { ingestRecord } = await import("../../packages/intel/src/ingest");
  const ids: string[] = [];
  let processed = 0,
    added = 0,
    updated = 0,
    rejected = 0;
  const offset = z
    .number()
    .int()
    .min(0)
    .parse(job.payload.offset ?? 0);
  for (const [localIndex, item] of items.slice(offset, offset + 10).entries()) {
    const index = offset + localIndex;
    let records;
    try {
      records = await feed.normalize(item);
      for (const record of records) {
        RecordSchema.parse(record);
        if (record.observable)
          await normalise(record.observable.value, record.observable.type);
      }
    } catch (error) {
      // Database/upstream errors are retryable; malformed source records are quarantined.
      if (
        error instanceof Error &&
        /D1_|SQLITE|network|fetch/i.test(error.message)
      )
        throw error;
      rejected++;
      await env.DB.prepare(
        "INSERT OR IGNORE INTO feed_rejections VALUES(?,?,?,?,?,?,?)",
      )
        .bind(
          job.jobId + ":" + index,
          job.entityId,
          job.jobId,
          String(job.payload.rawKey),
          index,
          error instanceof Error ? error.constructor.name : "InvalidRecord",
          new Date().toISOString(),
        )
        .run();
      continue;
    }
    for (const record of records) {
      const recordId =
        record.entity?.id ??
        (record.observable
          ? (await normalise(record.observable.value, record.observable.type))
              .id
          : record.relationships[0]?.id);
      const existed = recordId ? await repo.entity(recordId) : null;
      const id = await ingestRecord(repo, record, String(job.payload.rawKey));
      if (id) {
        ids.push(id);
        if (existed) updated++;
        else added++;
      }
    }
    processed++;
  }
  for (const id of ids)
    await repo.enqueue({
      ...makeJob("enrich", id, undefined, {}, job.correlationId),
      jobId: job.jobId + ":enrich:" + id,
    });
  await repo.finish(
    job,
    { processed, added, updated, rejected },
    offset + 10 < items.length
      ? {
          ...job,
          jobId: job.jobId + ":page:" + (offset + 10),
          payload: { ...job.payload, offset: offset + 10 },
        }
      : undefined,
  );
}
export async function finalizeFeeds(env: AppEnv) {
  const roots = await env.DB.prepare(
    "SELECT data,result FROM pipeline_jobs WHERE stage='feed-sync' AND status='complete' AND json_extract(result,'$.finalized') IS NULL ORDER BY created_at LIMIT 10",
  ).all<{ data: string; result: string }>();
  for (const row of roots.results) {
    const job = JobSchema.parse(JSON.parse(row.data));
    const pending = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM pipeline_jobs WHERE json_extract(data,'$.correlationId')=? AND id!=? AND status!='complete'",
    )
      .bind(job.correlationId, job.jobId)
      .first<{ n: number }>();
    if (pending?.n) {
      const failed = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM pipeline_jobs WHERE json_extract(data,'$.correlationId')=? AND status='failed'",
      )
        .bind(job.correlationId)
        .first<{ n: number }>();
      if (failed?.n)
        await env.DB.prepare(
          "UPDATE sources SET status='error',last_error='Processing jobs exhausted retries; replay failed feed jobs' WHERE id=?",
        )
          .bind(job.entityId)
          .run();
      continue;
    }
    const result = z
      .object({
        checkpoint: z.string(),
        more: z.boolean().optional(),
        records: z.number(),
        rawKey: z.string(),
      })
      .parse(JSON.parse(row.result));
    const totals = await env.DB.prepare(
      "SELECT COALESCE(SUM(json_extract(result,'$.added')),0) AS added, COALESCE(SUM(json_extract(result,'$.updated')),0) AS updated, COALESCE(SUM(json_extract(result,'$.rejected')),0) AS rejected FROM pipeline_jobs WHERE stage='normalise' AND json_extract(data,'$.payload.feedJobId')=?",
    )
      .bind(job.jobId)
      .first<{ added: number; updated: number; rejected: number }>();
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE sources SET status=?,last_sync=?,next_sync=?,records_processed=records_processed+?,records_added=records_added+?,records_updated=records_updated+?,errors=errors+?,last_error=? WHERE id=?",
      ).bind(
        totals?.rejected ? "degraded" : "healthy",
        new Date().toISOString(),
        new Date(Date.now() + 21600000).toISOString(),
        result.records,
        totals?.added ?? 0,
        totals?.updated ?? 0,
        totals?.rejected ?? 0,
        totals?.rejected ? "Malformed records quarantined" : null,
        job.entityId,
      ),
      env.DB.prepare(
        "INSERT INTO feed_checkpoints VALUES(?,?,?) ON CONFLICT(source_id) DO UPDATE SET checkpoint=excluded.checkpoint,updated_at=excluded.updated_at",
      ).bind(job.entityId, result.checkpoint, new Date().toISOString()),
      env.DB.prepare(
        "DELETE FROM feed_locks WHERE source_id=? AND job_id=?",
      ).bind(job.entityId, job.jobId),
      env.DB.prepare("UPDATE pipeline_jobs SET result=? WHERE id=?").bind(
        JSON.stringify({ ...result, finalized: true }),
        job.jobId,
      ),
    ]);
    if (result.more) await queueFeedSync(env, job.entityId);
  }
}

export async function queueFeedSync(
  env: AppEnv,
  sourceId: string,
  correlationId: string = crypto.randomUUID(),
) {
  const repo = new Repository(env.DB);
  const job = makeJob("feed-sync", sourceId, undefined, {}, correlationId);
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO feed_locks VALUES(?,?,?)").bind(
      sourceId,
      job.jobId,
      now,
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO pipeline_jobs(id,tenant_id,entity_id,stage,status,data,created_at,updated_at) SELECT ?,NULL,?,'feed-sync','queued',?,?,? WHERE EXISTS(SELECT 1 FROM feed_locks WHERE source_id=? AND job_id=?)",
    ).bind(
      job.jobId,
      sourceId,
      JSON.stringify(job),
      now,
      now,
      sourceId,
      job.jobId,
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO outbox(id,queue,data,created_at) SELECT ?,'ingest',?,? WHERE EXISTS(SELECT 1 FROM feed_locks WHERE source_id=? AND job_id=?)",
    ).bind(job.jobId, JSON.stringify(job), now, sourceId, job.jobId),
  ]);
  const lock = await env.DB.prepare(
    "SELECT job_id FROM feed_locks WHERE source_id=?",
  )
    .bind(sourceId)
    .first<{ job_id: string }>();
  if (!lock) throw new Error("Feed sync reservation missing");
  const existing = await repo.queuedMessage(lock.job_id);
  if (!existing) throw new Error("Feed sync reservation inconsistent");
  return existing;
}
