/** Isolated Miniflare ingestion benchmark; never touches deployed intelligence. */
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync, mkdirSync, writeFileSync } from "node:fs";
import { z } from "zod";
import { migrationStatements } from "../packages/database/src/migrations";
import { Repository } from "../packages/database/src/repository";
import { ingestRecord } from "../packages/intel/src/ingest";
import { RecordSchema } from "../packages/schemas/src/index";
async function main() {
  const count = z.coerce
    .number()
    .int()
    .min(100)
    .max(100000)
    .parse(process.argv[2] ?? 10000);
  const unique = Math.floor(count / 2),
    concurrency = 8;
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("benchmark")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  try {
    const db = await mf.getD1Database("DB"),
      repo = new Repository(db);
    for (const f of readdirSync("migrations").sort())
      for (const sql of migrationStatements(
        readFileSync("migrations/" + f, "utf8"),
      ))
        await db.prepare(sql).run();
    await db
      .prepare(
        "INSERT INTO sources(id,name,independent_group,reliability,license,redistributable) VALUES('synthetic-benchmark','Synthetic local workload','synthetic-benchmark',0.5,'Synthetic test',0)",
      )
      .run();
    const now = new Date().toISOString(),
      latencies: number[] = [];
    let cursor = 0;
    const start = performance.now();
    await Promise.all(
      Array.from({ length: concurrency }, async () => {
        while (cursor < count) {
          const i = cursor++,
            value = `bench-${i % unique}.example`;
          const begin = performance.now();
          await ingestRecord(
            repo,
            RecordSchema.parse({
              observable: {
                type: "domain",
                value: i % 2 ? value.toUpperCase() : value,
              },
              provenance: {
                sourceId: "synthetic-benchmark",
                sourceName: "Synthetic local workload",
                sourceRecordId: value,
                retrievedAt: now,
                redistributable: false,
              },
            }),
          );
          latencies.push(performance.now() - begin);
        }
      }),
    );
    const ms = performance.now() - start;
    const stored = await db
      .prepare("SELECT COUNT(*) AS count FROM observables")
      .first<{ count: number }>();
    if (stored?.count !== unique)
      throw new Error("Deterministic deduplication failed");
    latencies.sort((a, b) => a - b);
    const percentile = (p: number) =>
      Number(
        latencies[
          Math.min(latencies.length - 1, Math.floor(latencies.length * p))
        ]!.toFixed(2),
      );
    const result = {
      kind: "local-miniflare-ingestion",
      created_at: now,
      input_records: count,
      unique_observables: stored.count,
      duplicates_converged: count - stored.count,
      concurrency,
      duration_ms: Math.round(ms),
      records_per_second: Number((count / (ms / 1000)).toFixed(2)),
      latency_ms: {
        p50: percentile(0.5),
        p95: percentile(0.95),
        p99: percentile(0.99),
      },
      notice:
        "Measures normalization, identity, provenance and D1 persistence on this machine. Excludes remote feeds, network, Queues, AI and concurrent analyst traffic; not a Cloudflare capacity or SLA claim.",
    };
    mkdirSync("artifacts", { recursive: true });
    writeFileSync("artifacts/benchmark.json", JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result));
  } finally {
    await mf.dispose();
  }
}
main().catch((e) => {
  console.error(e instanceof Error ? e.message : "Benchmark failed");
  process.exitCode = 1;
});
