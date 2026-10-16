import { afterAll, beforeAll, expect, it } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { Repository } from "../packages/database/src/repository";
import { normalise } from "../packages/intel/src/normalise";
import type { Evidence } from "../packages/schemas/src/index";

let mf: Miniflare, db: D1Database, repo: Repository;
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
  await db
    .prepare(
      "INSERT INTO tenants(id,name,created_at) VALUES('event-tests','Events','2026-01-01T00:00:00.000Z')",
    )
    .run();
  await db
    .prepare(
      "INSERT INTO workspace_objects VALUES('event-tests','event-watch','watchlist','Event regression','active','medium','test-user',1,'test-change','{}','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
    )
    .run();
});
afterAll(async () => {
  await mf.dispose();
});

it("new observation dates and confidence notify subscriptions, while repeated collection metadata does not", async () => {
  const provenance = {
    sourceId: "mitre",
    sourceName: "MITRE",
    retrievedAt: "2026-01-01T00:00:00.000Z",
    redistributable: true,
  };
  const observable = await normalise("event-regression.example");
  await repo.putObservable(observable, provenance);
  const original: Evidence = {
    id: "material-event-evidence",
    sourceId: "mitre",
    type: "feed",
    provenance,
    observedAt: "2026-01-01T00:00:00.000Z",
    createdAt: "2026-01-01T00:00:00.000Z",
    confidence: 0.7,
    behavioural: false,
    data: { malicious: true },
    rawKey: "original.json",
  };
  await repo.putEvidence(observable.id, original);
  const count = async () =>
    (await db
      .prepare(
        "SELECT COUNT(*) AS n FROM intelligence_changes WHERE reference_id=? AND event_type='evidence.updated'",
      )
      .bind(original.id)
      .first<{ n: number }>())!.n;
  await repo.putEvidence(observable.id, {
    ...original,
    createdAt: "2026-01-02T00:00:00.000Z",
    provenance: { ...provenance, retrievedAt: "2026-01-02T00:00:00.000Z" },
    rawKey: "recollected.json",
  });
  expect(await count()).toBe(0);
  const refreshed = { ...original, observedAt: "2026-01-02T00:00:00.000Z" };
  await repo.putEvidence(observable.id, refreshed);
  expect(await count()).toBe(1);
  await repo.putEvidence(observable.id, { ...refreshed, confidence: 0.9 });
  expect(await count()).toBe(2);
});
