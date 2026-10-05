import type { AppEnv } from "../../apps/api/src/env";
import { Repository } from "../../packages/database/src/repository";
import {
  JobSchema,
  RecordSchema,
  type PipelineJob,
} from "../../packages/schemas/src/index";
import { errorType, log } from "../../packages/observability/src/index";
import { classify } from "../classify/index";
import { ingestRecord } from "../../packages/intel/src/ingest";
import { z } from "zod";
import {
  syncFeed,
  finalizeFeeds,
  fanoutFeed,
  normalizeFeedChunk,
} from "../feed-sync/index";
import { exportAssessment } from "../export/index";
import { processBulk } from "./upload";
import { enrichEntity } from "../enrich/index";
import { correlate } from "../correlate/index";

export function makeJob(
  stage: PipelineJob["stage"],
  entityId: string,
  tenantId?: string,
  payload: Record<string, unknown> = {},
  correlationId: string = crypto.randomUUID(),
): PipelineJob {
  return {
    jobId: crypto.randomUUID(),
    tenantId,
    entityId,
    stage,
    attempt: 0,
    createdAt: new Date().toISOString(),
    correlationId,
    payload,
  };
}
function next(
  job: PipelineJob,
  stage: PipelineJob["stage"],
  entityId = job.entityId,
): PipelineJob {
  return {
    ...job,
    jobId: job.jobId + ":" + stage,
    stage,
    entityId,
    attempt: 0,
  };
}
export async function dispatchOutbox(env: AppEnv) {
  const rows = await env.DB.prepare(
    "SELECT id,queue,data FROM outbox WHERE dispatched_at IS NULL ORDER BY created_at LIMIT 100",
  ).all<{ id: string; queue: string; data: string }>();
  const bindings: Record<string, Queue> = {
    ingest: env.INGEST_QUEUE,
    normalise: env.NORMALISE_QUEUE,
    enrich: env.ENRICH_QUEUE,
    correlate: env.CORRELATE_QUEUE,
    classify: env.CLASSIFY_QUEUE,
    export: env.EXPORT_QUEUE,
  };
  for (const row of rows.results) {
    const queue = bindings[row.queue];
    if (!queue) throw new Error("Unknown outbox queue");
    await queue.send(JobSchema.parse(JSON.parse(row.data)));
    await env.DB.prepare("UPDATE outbox SET dispatched_at=? WHERE id=?")
      .bind(new Date().toISOString(), row.id)
      .run();
  }
  return rows.results.length;
}
export async function processJob(env: AppEnv, job: PipelineJob) {
  const repo = new Repository(env.DB);
  switch (job.stage) {
    case "feed-sync":
      await syncFeed(env, job);
      return;
    case "bulk":
      await processBulk(env, job);
      return;
    case "ingest":
      if (job.payload.mode === "feed-fanout") {
        await fanoutFeed(env, job);
        return;
      }
      await repo.finish(job, {}, next(job, "normalise"));
      return;
    case "normalise": {
      if (job.payload.feedChunk) {
        await normalizeFeedChunk(env, job);
        return;
      }
      let ids: string[] = [];
      if (job.payload.records) {
        const records = z.array(RecordSchema).parse(job.payload.records);
        for (const r of records) {
          const id = await ingestRecord(
            repo,
            r,
            typeof job.payload.rawKey === "string"
              ? job.payload.rawKey
              : undefined,
          );
          if (id) ids.push(id);
        }
      } else if (job.payload.rawRecordKey) {
        const archive = await env.ARCHIVE.get(String(job.payload.rawRecordKey));
        if (!archive) throw new Error("Missing archived record");
        const records = z.array(RecordSchema).parse(await archive.json());
        for (const r of records) {
          const id = await ingestRecord(
            repo,
            r,
            String(job.payload.rawKey ?? job.payload.rawRecordKey),
          );
          if (id) ids.push(id);
        }
      } else ids = [job.entityId];
      const observableId = ids.find((id) => id.startsWith("obs_"));
      await repo.finish(
        job,
        { entityIds: ids },
        observableId ? next(job, "enrich", observableId) : undefined,
      );
      return;
    }
    case "enrich":
      await repo.finish(
        job,
        await enrichEntity(env, job.entityId),
        next(job, "correlate"),
      );
      return;
    case "correlate":
      await correlate(repo, job.entityId);
      await repo.finish(
        job,
        { correlated: true },
        job.tenantId ? next(job, "classify") : undefined,
      );
      return;
    case "classify":
      if (!job.tenantId) throw new Error("Classification requires tenant");
      {
        const a = await classify(
          env,
          job.tenantId,
          job.entityId,
          job.payload.force === true,
        );
        await repo.finish(
          job,
          { assessmentId: a.assessment_id },
          next(
            {
              ...job,
              payload: { ...job.payload, assessmentId: a.assessment_id },
            },
            "export",
          ),
        );
        return;
      }
    case "export":
      if (!job.tenantId) throw new Error("Export requires tenant");
      {
        const id = z.string().parse(job.payload.assessmentId);
        const exported = await exportAssessment(env, job.tenantId, id);
        await repo.finish(job, exported);
        return;
      }
  }
}
export async function consume(batch: MessageBatch<unknown>, env: AppEnv) {
  for (const message of batch.messages) {
    const parsed = JobSchema.safeParse(message.body);
    if (!parsed.success) {
      await env.ARCHIVE.put(
        "quarantine/" + batch.queue + "/" + crypto.randomUUID() + ".json",
        JSON.stringify(message.body),
      );
      log({
        stage: "queue",
        result: "poison-message",
        error_type: "InvalidJobSchema",
      });
      message.ack();
      continue;
    }
    const job = parsed.data;
    const repo = new Repository(env.DB);
    if (/^intel-dead-letter(?:-(?:staging|production))?$/.test(batch.queue)) {
      await env.DB.prepare(
        "UPDATE pipeline_jobs SET status='failed',error_type='RetriesExhausted',updated_at=? WHERE id=?",
      )
        .bind(new Date().toISOString(), job.jobId)
        .run();
      message.ack();
      continue;
    }
    const start = Date.now();
    try {
      if (!(await repo.claim(job))) {
        const state = await env.DB.prepare(
          "SELECT status FROM pipeline_jobs WHERE id=?",
        )
          .bind(job.jobId)
          .first<{ status: string }>();
        if (state?.status === "running") message.retry({ delaySeconds: 60 });
        else message.ack();
        continue;
      }
      await processJob(env, job);
      message.ack();
      log({
        job_id: job.jobId,
        tenant_id: job.tenantId,
        correlation_id: job.correlationId,
        stage: job.stage,
        duration_ms: Date.now() - start,
        result: "complete",
      });
    } catch (error) {
      await env.DB.prepare(
        "UPDATE pipeline_jobs SET status='queued',lease_until=NULL,error_type=?,updated_at=? WHERE id=?",
      )
        .bind(errorType(error), new Date().toISOString(), job.jobId)
        .run();
      log({
        job_id: job.jobId,
        tenant_id: job.tenantId,
        correlation_id: job.correlationId,
        stage: job.stage,
        duration_ms: Date.now() - start,
        result: "retry",
        error_type: errorType(error),
      });
      message.retry({ delaySeconds: Math.min(300, 2 ** message.attempts * 5) });
    }
  }
  await dispatchOutbox(env);
  await finalizeFeeds(env);
}
