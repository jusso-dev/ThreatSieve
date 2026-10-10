import { beforeAll, afterAll, beforeEach, it, expect, vi } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { Repository } from "../packages/database/src/repository";
import { makeJob, consume } from "../workers/ingest/pipeline";
import {
  deadLetter,
  dispatchOutbox,
  recoverExpiredJobs,
  replayJob,
} from "../workers/ingest/reliability";
import type { AppEnv } from "../apps/api/src/env";
import type { PipelineJob } from "../packages/schemas/src/index";
let mf: Miniflare, db: D1Database, repo: Repository, env: AppEnv;
const sent: PipelineJob[] = [];
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  repo = new Repository(db);
  for (const file of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + file, "utf8"),
    ))
      await db.prepare(sql).run();
  // Only queue publication is substituted; leases, transactions and job state use real local D1.
  const queue = {
    sendBatch: vi.fn(async (messages: { body: PipelineJob }[]) => {
      sent.push(...messages.map((m) => m.body));
    }),
  } as unknown as Queue;
  env = {
    DB: db,
    INGEST_QUEUE: queue,
    OPERATIONS_QUEUE: queue,
    NORMALISE_QUEUE: queue,
    ENRICH_QUEUE: queue,
    CORRELATE_QUEUE: queue,
    CLASSIFY_QUEUE: queue,
    EXPORT_QUEUE: queue,
  } as AppEnv;
});
afterAll(async () => {
  await mf.dispose();
});
beforeEach(async () => {
  await db.batch([
    db.prepare("DELETE FROM outbox"),
    db.prepare("DELETE FROM pipeline_jobs"),
  ]);
  sent.length = 0;
});
it("operations jobs publish on their own queue", async () => {
  const published: PipelineJob[] = [];
  const operations = {
    sendBatch: vi.fn(async (messages: { body: PipelineJob }[]) => {
      published.push(...messages.map((m) => m.body));
    }),
  } as unknown as Queue;
  const ingest = {
    sendBatch: vi.fn(async () => {
      throw new Error("operations must not use ingest");
    }),
  } as unknown as Queue;
  await repo.enqueue(makeJob("operations", "entity"));
  await dispatchOutbox({
    ...env,
    OPERATIONS_QUEUE: operations,
    INGEST_QUEUE: ingest,
  });
  expect(published.map((job) => job.stage)).toEqual(["operations"]);
  expect(ingest.sendBatch).not.toHaveBeenCalled();
});
it("concurrent dispatchers reserve each outbox item once", async () => {
  for (let i = 0; i < 25; i++)
    await repo.enqueue(makeJob("enrich", "entity-" + i));
  await Promise.all(Array.from({ length: 8 }, () => dispatchOutbox(env)));
  expect(sent).toHaveLength(25);
  expect(new Set(sent.map((j) => j.jobId)).size).toBe(25);
  expect(await dispatchOutbox(env)).toBe(0);
});
it("late dead letters cannot overwrite completed results", async () => {
  const job = makeJob("enrich", "entity");
  await repo.enqueue(job);
  await repo.claim(job);
  await repo.finish(job, { embedded: false });
  await deadLetter(db, job);
  const state = await db
    .prepare("SELECT status,result,error_type FROM pipeline_jobs WHERE id=?")
    .bind(job.jobId)
    .first();
  expect(state).toEqual({
    status: "complete",
    result: JSON.stringify({ embedded: false }),
    error_type: null,
  });
});
it("duplicate deliveries acknowledge without consuming the active owner's retries", async () => {
  const job = makeJob("enrich", "entity");
  await repo.enqueue(job);
  await repo.claim(job);
  const ack = vi.fn(),
    retry = vi.fn();
  await consume(
    {
      queue: "intel-enrich",
      messages: [{ body: job, ack, retry, attempts: 5 }],
    } as unknown as MessageBatch<unknown>,
    env,
  );
  expect(ack).toHaveBeenCalledOnce();
  expect(retry).not.toHaveBeenCalled();
  await deadLetter(db, job);
  expect(
    (
      await db
        .prepare("SELECT status FROM pipeline_jobs WHERE id=?")
        .bind(job.jobId)
        .first()
    )?.status,
  ).toBe("running");
});
it("manual replay fences old messages and late completion from the previous generation", async () => {
  const job = makeJob("enrich", "entity");
  await repo.enqueue(job);
  await deadLetter(db, job);
  expect(await replayJob(db, job.jobId)).toBe(true);
  await deadLetter(db, job);
  expect(await repo.claim(job)).toBe(false);
  const child = {
    ...job,
    jobId: job.jobId + ":old-child",
    stage: "correlate" as const,
  };
  await repo.finish(job, { stale: true }, child);
  expect(await repo.queuedMessage(child.jobId)).toBeNull();
  const current = await repo.queuedMessage(job.jobId);
  expect(current?.generation).toBe(1);
  expect(await repo.claim(current!)).toBe(true);
  await repo.finish(current!, { ok: true });
  expect(await replayJob(db, job.jobId)).toBe(false);
});
it("expired leases recover through the outbox, then stop at the execution budget", async () => {
  const job = makeJob("enrich", "entity");
  await repo.enqueue(job);
  await repo.claim(job);
  await db
    .prepare(
      "UPDATE pipeline_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?",
    )
    .bind(job.jobId)
    .run();
  expect(await repo.claim(job)).toBe(false);
  expect(await recoverExpiredJobs(db)).toBe(1);
  await dispatchOutbox(env);
  expect(sent[0]!.generation).toBe(1);
  await repo.claim(sent[0]!);
  await db
    .prepare(
      "UPDATE pipeline_jobs SET attempt=6,lease_until='2000-01-01T00:00:00.000Z' WHERE id=?",
    )
    .bind(job.jobId)
    .run();
  await recoverExpiredJobs(db);
  expect(
    await db
      .prepare("SELECT status,error_type FROM pipeline_jobs WHERE id=?")
      .bind(job.jobId)
      .first(),
  ).toEqual({ status: "failed", error_type: "LeaseRetriesExhausted" });
});
it("failed queue publication releases reservations without discarding pending work", async () => {
  const job = makeJob("enrich", "entity");
  await repo.enqueue(job);
  const failed = {
    ...env,
    ENRICH_QUEUE: {
      sendBatch: async () => {
        throw new Error("Provider unavailable");
      },
    } as unknown as Queue,
  };
  await expect(dispatchOutbox(failed)).rejects.toThrow("Provider unavailable");
  expect(await dispatchOutbox(env)).toBe(1);
  expect(sent[0]!.jobId).toBe(job.jobId);
});

it("feed finalization advances the checkpoint and counts exactly once under concurrency", async () => {
  const { queueFeedSync, finalizeFeeds } =
    await import("../workers/feed-sync/index");
  const root = await queueFeedSync(env, "feodo");
  await repo.finish(root, {
    rawKey: "raw/test.json",
    records: 7,
    checkpoint: "accepted",
  });
  await Promise.all([
    finalizeFeeds(env),
    finalizeFeeds(env),
    finalizeFeeds(env),
  ]);
  expect(
    (
      await db
        .prepare("SELECT records_processed FROM sources WHERE id='feodo'")
        .first()
    )?.records_processed,
  ).toBe(7);
  expect(
    (
      await db
        .prepare(
          "SELECT checkpoint FROM feed_checkpoints WHERE source_id='feodo'",
        )
        .first()
    )?.checkpoint,
  ).toBe("accepted");
});

it("a batch of completed duplicate deliveries acknowledges without republishing work", async () => {
  const job = makeJob("enrich", "already-completed");
  await repo.enqueue(job);
  await repo.finish(job, { embedded: false });
  const messages = Array.from({ length: 50 }, () => ({
    body: job,
    ack: vi.fn(),
    retry: vi.fn(),
    attempts: 1,
  }));
  await consume(
    {
      queue: "intel-enrich-production",
      messages,
    } as unknown as MessageBatch<unknown>,
    env,
  );
  for (const m of messages) {
    expect(m.ack).toHaveBeenCalledOnce();
    expect(m.retry).not.toHaveBeenCalled();
  }
  expect(sent).toHaveLength(0);
});
