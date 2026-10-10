import type { AppEnv } from "../../apps/api/src/env";
import { JobSchema, type PipelineJob } from "../../packages/schemas/src/index";

/** Reserve before publishing. Acceptance followed by a crash still permits at-least-once redelivery. */
export async function dispatchOutbox(env: AppEnv) {
  const token = crypto.randomUUID(),
    now = new Date().toISOString();
  await env.DB.prepare(
    "UPDATE outbox SET dispatch_token=?,lease_until=? WHERE id IN (SELECT id FROM outbox WHERE dispatched_at IS NULL AND (lease_until IS NULL OR lease_until<?) ORDER BY created_at,id LIMIT 100)",
  )
    .bind(token, new Date(Date.now() + 300000).toISOString(), now)
    .run();
  const rows = await env.DB.prepare(
    "SELECT id,queue,data FROM outbox WHERE dispatch_token=? AND dispatched_at IS NULL",
  )
    .bind(token)
    .all<{ id: string; queue: string; data: string }>();
  const bindings: Record<string, Queue> = {
    ingest: env.INGEST_QUEUE,
    operations: env.OPERATIONS_QUEUE,
    normalise: env.NORMALISE_QUEUE,
    enrich: env.ENRICH_QUEUE,
    correlate: env.CORRELATE_QUEUE,
    classify: env.CLASSIFY_QUEUE,
    export: env.EXPORT_QUEUE,
  };
  try {
    for (const name of new Set(rows.results.map((r) => r.queue))) {
      const queue = bindings[name];
      if (!queue) throw new Error("Unknown outbox queue");
      const group = rows.results.filter((r) => r.queue === name);
      await queue.sendBatch(
        group.map((r) => ({ body: JobSchema.parse(JSON.parse(r.data)) })),
      );
      await env.DB.prepare(
        "UPDATE outbox SET dispatched_at=?,lease_until=NULL,dispatch_token=NULL WHERE dispatch_token=? AND queue=?",
      )
        .bind(new Date().toISOString(), token, name)
        .run();
    }
  } finally {
    await env.DB.prepare(
      "UPDATE outbox SET lease_until=NULL,dispatch_token=NULL WHERE dispatch_token=?",
    )
      .bind(token)
      .run();
  }
  return rows.results.length;
}

/** A late DLQ delivery must never undo committed work or a newer manual replay. */
export async function deadLetter(db: D1Database, job: PipelineJob) {
  const now = new Date().toISOString();
  await db
    .prepare(
      "UPDATE pipeline_jobs SET status='failed',error_type=COALESCE(error_type,'RetriesExhausted'),lease_until=NULL,updated_at=? WHERE id=? AND result IS NULL AND status!='complete' AND COALESCE(json_extract(data,'$.generation'),0)=? AND (status!='running' OR lease_until<?)",
    )
    .bind(now, job.jobId, job.generation ?? 0, now)
    .run();
}

/** Reset delivery generation transactionally so previously queued copies become harmless. */
export async function replayJob(
  db: D1Database,
  id: string,
  expectedStatus = "failed",
) {
  const now = new Date().toISOString();
  const result = await db.batch([
    db
      .prepare(
        "UPDATE pipeline_jobs SET status='queued',attempt=0,error_type=NULL,lease_until=NULL,data=json_set(data,'$.generation',COALESCE(json_extract(data,'$.generation'),0)+1),updated_at=? WHERE id=? AND status=? AND result IS NULL",
      )
      .bind(now, id, expectedStatus),
    db
      .prepare(
        "UPDATE outbox SET data=(SELECT data FROM pipeline_jobs WHERE id=?),dispatched_at=NULL,lease_until=NULL,dispatch_token=NULL WHERE id=? AND EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND status='queued' AND updated_at=?)",
      )
      .bind(id, id, id, now),
  ]);
  return result[0]!.meta.changes > 0;
}

/** Recover abandoned consumers, not ordinary queued messages which Cloudflare may still be delivering. */
export async function recoverExpiredJobs(db: D1Database) {
  const now = new Date().toISOString();
  const rows = await db
    .prepare(
      "SELECT id,attempt FROM pipeline_jobs WHERE status='running' AND lease_until<? AND result IS NULL ORDER BY lease_until LIMIT 100",
    )
    .bind(now)
    .all<{ id: string; attempt: number }>();
  for (const row of rows.results) {
    if (row.attempt >= 6) {
      await db
        .prepare(
          "UPDATE pipeline_jobs SET status='failed',error_type='LeaseRetriesExhausted',lease_until=NULL,updated_at=? WHERE id=? AND status='running' AND lease_until<? AND result IS NULL",
        )
        .bind(now, row.id, now)
        .run();
      continue;
    }
    await db.batch([
      db
        .prepare(
          "UPDATE pipeline_jobs SET status='queued',lease_until=NULL,error_type='LeaseExpired',data=json_set(data,'$.generation',COALESCE(json_extract(data,'$.generation'),0)+1),updated_at=? WHERE id=? AND status='running' AND lease_until<? AND result IS NULL",
        )
        .bind(now, row.id, now),
      db
        .prepare(
          "UPDATE outbox SET data=(SELECT data FROM pipeline_jobs WHERE id=?),dispatched_at=NULL,lease_until=NULL,dispatch_token=NULL WHERE id=? AND EXISTS(SELECT 1 FROM pipeline_jobs WHERE id=? AND status='queued' AND updated_at=?)",
        )
        .bind(row.id, row.id, row.id, now),
    ]);
  }
  return rows.results.length;
}
