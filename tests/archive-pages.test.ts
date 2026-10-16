import { expect, it } from "vitest";
import {
  archivePageKey,
  partitionArchive,
} from "../packages/intel/src/archive-pages";

it("archive writes and page reads grow linearly up to the maximum upload size", async () => {
  for (const count of [1000, 10000, 100000]) {
    let writes = 0,
      bytes = 0,
      largest = 0;
    await partitionArchive(
      {
        async put(key, body) {
          expect(key).toBe(archivePageKey("upload", writes * 1000));
          const page = JSON.parse(body) as unknown[];
          expect(page.length).toBeLessThanOrEqual(1000);
          largest = Math.max(largest, Buffer.byteLength(body));
          bytes += Buffer.byteLength(body);
          writes++;
        },
      },
      "upload",
      Array.from({ length: count }, () => ({
        observable: "partition.example",
      })),
      1000,
    );
    expect(writes).toBe(count / 1000);
    expect(bytes).toBeLessThan(count * 40);
    expect(largest).toBeLessThan(40960);
  }
});

it("feed fanout reads bounded pages and redelivery publishes each child once", async () => {
  const { Miniflare } = await import("miniflare");
  const { readFileSync, readdirSync } = await import("node:fs");
  const { migrationStatements } =
    await import("../packages/database/src/migrations");
  const { Repository } = await import("../packages/database/src/repository");
  const { makeJob } = await import("../workers/ingest/pipeline");
  const { fanoutFeed } = await import("../workers/feed-sync/index");
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  try {
    const db = await mf.getD1Database("DB");
    for (const name of readdirSync("migrations").sort())
      for (const sql of migrationStatements(
        readFileSync("migrations/" + name, "utf8"),
      ))
        await db.prepare(sql).run();
    const objects = new Map<string, string>(),
      reads: string[] = [];
    const archive = {
      async put(key: string, body: string) {
        objects.set(key, body);
      },
      async get(key: string) {
        reads.push(key);
        const body = objects.get(key);
        return body === undefined
          ? null
          : {
              async json() {
                return JSON.parse(body);
              },
            };
      },
    };
    const key = "raw/feed/partition.json",
      root = "bounded-feed";
    await partitionArchive(
      archive,
      key,
      Array.from({ length: 1200 }, (_, i) => ({ id: i })),
      500,
    );
    const job = makeJob("ingest", "feodo", undefined, {
      mode: "feed-fanout",
      partitioned: true,
      pageSize: 500,
      recordsKey: key,
      rawKey: "raw/original",
      offset: 0,
      total: 1200,
      feedJobId: root,
      checkpoint: "checkpoint",
    });
    const repo = new Repository(db);
    await repo.enqueue(job);
    const env = {
      DB: db,
      ARCHIVE: archive,
    } as unknown as import("../apps/api/src/env").AppEnv;
    await fanoutFeed(env, job);
    for (const offset of [500, 1000]) {
      const row = await db
        .prepare("SELECT data FROM pipeline_jobs WHERE id=?")
        .bind(root + ":fanout:" + offset)
        .first<{ data: string }>();
      await fanoutFeed(env, JSON.parse(row!.data));
    }
    expect(reads).toEqual([0, 500, 1000].map((n) => archivePageKey(key, n)));
    expect(objects.has(key)).toBe(false);
    await fanoutFeed(env, job);
    expect(
      (
        await db
          .prepare(
            "SELECT COUNT(*) AS n FROM pipeline_jobs WHERE stage='normalise'",
          )
          .first<{ n: number }>()
      )?.n,
    ).toBe(120);
    expect(
      (
        await db
          .prepare("SELECT COUNT(*) AS n FROM outbox WHERE queue='normalise'")
          .first<{ n: number }>()
      )?.n,
    ).toBe(120);
  } finally {
    await mf.dispose();
  }
});
