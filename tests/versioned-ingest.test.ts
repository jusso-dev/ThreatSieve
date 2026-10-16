import { beforeAll, afterAll, expect, it } from "vitest";
import { Miniflare } from "miniflare";
import { readdirSync, readFileSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { Repository } from "../packages/database/src/repository";
import { RecordSchema, type PipelineJob } from "../packages/schemas/src/index";
import {
  ingestVersionedRecord,
  materialVersion,
} from "../packages/intel/src/versioned-ingest";
import { makeJob } from "../workers/ingest/pipeline";
import { normalise } from "../packages/intel/src/normalise";

let mf: Miniflare;
let db: D1Database;
const time = (n: number) => new Date(Date.UTC(2026, 9, 16, 0, n)).toISOString();
const record = (name: string, observedAt = time(1)) =>
  RecordSchema.parse({
    observable: { value: name },
    provenance: {
      sourceId: "feodo",
      sourceName: "Feodo",
      sourceRecordId: name,
      retrievedAt: time(1),
      redistributable: true,
    },
    evidence: [
      {
        id: "ev_" + name,
        type: "feed",
        sourceId: "feodo",
        provenance: {
          sourceId: "feodo",
          sourceName: "Feodo",
          sourceRecordId: name,
          retrievedAt: time(1),
          redistributable: true,
        },
        data: { malicious: true },
        confidence: 0.8,
        observedAt,
        createdAt: time(1),
      },
    ],
  });
async function parent(minute: number) {
  const job = { ...makeJob("normalise", "feodo"), createdAt: time(minute) };
  await new Repository(db).enqueue(job);
  return job;
}
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  for (const name of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + name, "utf8"),
    ))
      await db.prepare(sql).run();
});
afterAll(async () => {
  await mf.dispose();
});

it("material versions exclude processing clocks but retain observations and confidence", async () => {
  const a = record("material.example");
  const b = structuredClone(a);
  b.provenance.retrievedAt = time(9);
  b.evidence[0]!.createdAt = time(9);
  b.evidence[0]!.provenance.retrievedAt = time(9);
  b.evidence[0]!.rawKey = "a/new/archive";
  expect(await materialVersion(a)).toBe(await materialVersion(b));
  b.evidence[0]!.observedAt = time(2);
  expect(await materialVersion(a)).not.toBe(await materialVersion(b));
  b.evidence[0]!.observedAt = a.evidence[0]!.observedAt;
  b.evidence[0]!.confidence = 0.3;
  expect(await materialVersion(a)).not.toBe(await materialVersion(b));
});
it("skips unchanged delivery, preserves the ordering fence and processes real changes", async () => {
  const a = record("versioned.example");
  expect(
    (await ingestVersionedRecord(db, a, await parent(1), "raw/1")).changed,
  ).toBe(true);
  const later = structuredClone(a);
  later.provenance.retrievedAt = time(4);
  expect(
    (await ingestVersionedRecord(db, later, await parent(4), "raw/4")).changed,
  ).toBe(false);
  const old = record("versioned.example", time(2));
  expect(
    (await ingestVersionedRecord(db, old, await parent(2), "raw/2")).changed,
  ).toBe(false);
  const fresh = record("versioned.example", time(5));
  expect(
    (await ingestVersionedRecord(db, fresh, await parent(5), "raw/5")).changed,
  ).toBe(true);
  const id = (await normalise("versioned.example")).id;
  const jobs = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM pipeline_jobs WHERE stage='enrich' AND entity_id=?",
    )
    .bind(id)
    .first<{ n: number }>();
  expect(jobs?.n).toBe(2);
  expect((await new Repository(db).evidence(id))[0]?.observedAt).toBe(time(5));
});
it("rolls back content and version when downstream publication fails, then recovers once", async () => {
  const job = await parent(10),
    a = record("rollback-version.example");
  await db
    .prepare(
      "CREATE TRIGGER fail_version_delivery BEFORE INSERT ON outbox WHEN NEW.queue='enrich' BEGIN SELECT RAISE(ABORT,'injected delivery failure'); END",
    )
    .run();
  await expect(
    ingestVersionedRecord(db, a, job, "raw/failure"),
  ).rejects.toThrow();
  expect(
    await new Repository(db).observable(
      (await normalise("rollback-version.example")).id,
    ),
  ).toBeNull();
  expect(
    await db
      .prepare(
        "SELECT 1 FROM feed_record_versions WHERE source_id='feodo' AND collected_at=?",
      )
      .bind(time(10))
      .first(),
  ).toBeNull();
  await db.prepare("DROP TRIGGER fail_version_delivery").run();
  expect((await ingestVersionedRecord(db, a, job, "raw/retry")).changed).toBe(
    true,
  );
  expect((await ingestVersionedRecord(db, a, job, "raw/retry")).changed).toBe(
    false,
  );
  expect(
    await db.prepare("SELECT 1 FROM pipeline_commit_guard LIMIT 1").first(),
  ).toBeNull();
});
it("stale generations cannot write content or queue downstream work", async () => {
  const job = await parent(15);
  await db
    .prepare(
      "UPDATE pipeline_jobs SET data=json_set(data,'$.generation',1) WHERE id=?",
    )
    .bind(job.jobId)
    .run();
  const result = await ingestVersionedRecord(
    db,
    record("stale-version.example"),
    job,
    "raw/stale",
  );
  expect(result.changed).toBe(false);
  expect(
    await new Repository(db).observable(
      (await normalise("stale-version.example")).id,
    ),
  ).toBeNull();
});
it("concurrent equivalent snapshots create one enrichment", async () => {
  const a = record("concurrent-version.example");
  const jobs: PipelineJob[] = [await parent(20), await parent(21)];
  await Promise.all(
    jobs.map((job) => ingestVersionedRecord(db, a, job, "raw/concurrent")),
  );
  const id = (await normalise("concurrent-version.example")).id;
  expect(
    (
      await db
        .prepare(
          "SELECT COUNT(*) AS n FROM pipeline_jobs WHERE stage='enrich' AND entity_id=?",
        )
        .bind(id)
        .first<{ n: number }>()
    )?.n,
  ).toBe(1);
});

it("unchanged mirrored records preserve the canonical target and refreshed provenance", async () => {
  const p = {
    sourceId: "mitre",
    sourceName: "MITRE",
    retrievedAt: time(1),
    redistributable: true,
  };
  const entity = {
    id: "canonical-version-cve",
    type: "vulnerability" as const,
    name: "CVE-2026-99991",
    externalId: "CVE-2026-99991",
    description: "Canonical",
    aliases: [],
    data: {},
    provenance: p,
  };
  await new Repository(db).putEntity(entity);
  const imported = RecordSchema.parse({
    entity: {
      ...entity,
      id: "secondary-version-cve",
      provenance: {
        ...p,
        sourceId: "taxii",
        sourceName: "TAXII",
        sourceRecordId: "secondary-version-cve",
        sourceRecordNamespace: "stix",
      },
    },
    provenance: {
      ...p,
      sourceId: "taxii",
      sourceName: "TAXII",
      sourceRecordId: "secondary-version-cve",
      sourceRecordNamespace: "stix",
    },
  });
  expect(
    (
      await ingestVersionedRecord(
        db,
        imported,
        await parent(30),
        "raw/mirror-1",
      )
    ).id,
  ).toBe(entity.id);
  imported.provenance.retrievedAt = time(31);
  imported.entity!.provenance.retrievedAt = time(31);
  const same = await ingestVersionedRecord(
    db,
    imported,
    await parent(31),
    "raw/mirror-2",
  );
  expect(same).toMatchObject({ id: entity.id, changed: false });
  const row = await db
    .prepare(
      "SELECT provenance FROM entity_sources WHERE entity_id=? AND source_id='taxii'",
    )
    .bind(entity.id)
    .first<{ provenance: string }>();
  expect(JSON.parse(row!.provenance).retrievedAt).toBe(time(31));
});
