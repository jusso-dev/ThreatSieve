import { dispatchOutbox, deadLetter } from "./reliability";
import { deliverIntegration } from "../../packages/enterprise/src/integrations";
import {
  processOperation,
  scheduleOperations,
} from "../../packages/enterprise/src/automation";
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
export { dispatchOutbox } from "./reliability";
export async function processJob(env: AppEnv, job: PipelineJob) {
  const repo = new Repository(env.DB);
  switch (job.stage) {
    case "operations":
      if (job.payload.mode === "integration") {
        await deliverIntegration(env, job);
        return;
      }
      await processOperation(env.DB, job);
      return;
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
  const isDeadLetter = /^intel-dead-letter(?:-(?:staging|production))?$/.test(
    batch.queue,
  );
  // One bounded read per batch avoids a database write for every stale transport copy.
  const states = new Map<
    string,
    {
      id: string;
      status: string;
      generation: number;
      result: string | null;
      lease_until: string | null;
    }
  >();
  if (!isDeadLetter) {
    const ids = [
      ...new Set(
        batch.messages.flatMap((m) => {
          const p = JobSchema.safeParse(m.body);
          return p.success ? [p.data.jobId] : [];
        }),
      ),
    ];
    for (let offset = 0; offset < ids.length; offset += 80) {
      const chunk = ids.slice(offset, offset + 80);
      const rows = await env.DB.prepare(
        "SELECT id,status,COALESCE(json_extract(data,'$.generation'),0) AS generation,result,lease_until FROM pipeline_jobs WHERE id IN (" +
          chunk.map(() => "?").join(",") +
          ")",
      )
        .bind(...chunk)
        .all<{
          id: string;
          status: string;
          generation: number;
          result: string | null;
          lease_until: string | null;
        }>();
      for (const row of rows.results) states.set(row.id, row);
    }
  }
  const seen = new Set<string>();
  let processed = false;
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
    if (isDeadLetter) {
      await deadLetter(env.DB, job);
      message.ack();
      continue;
    }
    const state = states.get(job.jobId),
      delivery = job.jobId + ":" + (job.generation ?? 0);
    if (
      !state ||
      state.result !== null ||
      state.generation !== (job.generation ?? 0) ||
      state.status === "failed" ||
      state.status === "complete" ||
      (state.status === "running" &&
        state.lease_until &&
        state.lease_until > new Date().toISOString()) ||
      seen.has(delivery)
    ) {
      message.ack();
      continue;
    }
    seen.add(delivery);
    processed = true;
    const start = Date.now();
    try {
      if (!(await repo.claim(job))) {
        // The owner retains the lease. Cron recovers an abandoned owner; duplicate copies do not consume its retry budget.
        message.ack();
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
        "UPDATE pipeline_jobs SET status='queued',lease_until=NULL,error_type=?,updated_at=? WHERE id=? AND status='running' AND result IS NULL AND COALESCE(json_extract(data,'$.generation'),0)=?",
      )
        .bind(
          errorType(error),
          new Date().toISOString(),
          job.jobId,
          job.generation ?? 0,
        )
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
  if (processed) {
    await scheduleOperations(env.DB);
    await dispatchOutbox(env);
    await finalizeFeeds(env);
  }
}
