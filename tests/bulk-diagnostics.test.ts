import { migrationStatements } from "../packages/database/src/migrations";
import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { digest } from "../packages/intel/src/normalise";
import { app } from "../apps/api/src/index";
import { submitBulk } from "../workers/ingest/submission";
import { processBulk } from "../workers/ingest/upload";
import { workspaceMatchStatement } from "../packages/enterprise/src/intelligence";
import type { PipelineJob } from "../packages/schemas/src/index";
import type { AppEnv } from "../apps/api/src/env";
import type { Principal } from "../packages/schemas/src/index";

let mf: Miniflare;
let db: D1Database;
let archive: Awaited<ReturnType<Miniflare["getR2Bucket"]>>;

const principal: Principal = {
  tenantId: "tenant-bulk",
  userId: "analyst-bulk",
  keyId: "key-bulk",
  scopes: ["admin"],
  kind: "key",
};

beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
    r2Buckets: ["ARCHIVE"],
  });
  db = await mf.getD1Database("DB");
  archive = await mf.getR2Bucket("ARCHIVE");
  for (const name of readdirSync("migrations").sort()) {
    const sql = readFileSync("migrations/" + name, "utf8");
    for (const statement of migrationStatements(sql))
      await db.prepare(statement).run();
  }
  const now = new Date().toISOString();
  await db
    .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
    .bind("tenant-bulk", "Bulk", now)
    .run();
  await db
    .prepare(
      "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(
      "key-bulk",
      "tenant-bulk",
      "analyst-bulk",
      "Bulk test",
      await digest("bulk-test-key"),
      JSON.stringify(["admin"]),
      now,
    )
    .run();
});

afterAll(async () => {
  await mf?.dispose();
});

describe("bulk diagnostics (leaf 1.4.1)", () => {
  it("counts accepted, duplicates, and rejected; GET /v1/jobs/:id returns the shape", async () => {
    const inputs = [
      { observable: "bulk-unique.example" },
      { observable: "bulk-unique.example" },
      { observable: "not a valid indicator" },
    ];
    const submitted = await submitBulk(
      db,
      archive,
      principal,
      inputs,
      "bulk-diag-" + crypto.randomUUID(),
      "corr-bulk-diag",
    );
    const row = await db
      .prepare("SELECT data FROM pipeline_jobs WHERE id=?")
      .bind(submitted.job_id)
      .first<{ data: string }>();
    expect(row).toBeTruthy();
    const job = JSON.parse(row!.data) as PipelineJob;
    await processBulk({ DB: db, ARCHIVE: archive } as unknown as AppEnv, job);

    const finished = await db
      .prepare("SELECT result,status FROM pipeline_jobs WHERE id=?")
      .bind(submitted.job_id)
      .first<{ result: string; status: string }>();
    expect(finished?.status).toBe("complete");
    const shape = JSON.parse(finished!.result) as {
      processed: number;
      accepted: number;
      duplicates: number;
      rejected: number;
      errors: { index: number; error: string }[];
    };
    expect(shape).toMatchObject({
      processed: 3,
      accepted: 1,
      duplicates: 1,
      rejected: 1,
    });
    expect(shape.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          index: 2,
          error: expect.stringMatching(/invalid|ambiguous/i),
        }),
      ]),
    );

    const env = { DB: db, WEB_ORIGIN: "https://web.test" };
    const response = await app.request(
      "/v1/jobs/" + submitted.job_id,
      { headers: { Authorization: "Bearer bulk-test-key" } },
      env,
    );
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as {
      processed: number;
      accepted: number;
      duplicates: number;
      rejected: number;
      errors: { index: number; error: string }[];
      totals: {
        processed: number;
        accepted: number;
        duplicates: number;
        rejected: number;
      };
    };
    expect(body).toMatchObject({
      processed: 3,
      accepted: 1,
      duplicates: 1,
      rejected: 1,
    });
    expect(body.totals).toMatchObject({
      processed: 3,
      accepted: 1,
      duplicates: 1,
      rejected: 1,
    });
    expect(body.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          index: 2,
          error: expect.stringMatching(/invalid|ambiguous/i),
        }),
      ]),
    );
  });

  it("migration 0024 adds match_status and last_evaluated_at; matching writes set them", async () => {
    const cols = await db
      .prepare("PRAGMA table_info(workspace_matches)")
      .all<{ name: string }>();
    const names = new Set(cols.results.map((c) => c.name));
    expect(names.has("match_status")).toBe(true);
    expect(names.has("last_evaluated_at")).toBe(true);

    const now = new Date().toISOString();
    await db
      .prepare(
        "INSERT INTO workspace_objects VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
      )
      .bind(
        "tenant-bulk",
        "obj-match-1",
        "watchlist",
        "Match state",
        "active",
        "medium",
        "analyst-bulk",
        1,
        "change-match-1",
        JSON.stringify({
          id: "obj-match-1",
          kind: "watchlist",
          title: "Match state",
          status: "active",
          priority: "medium",
          ownerId: "analyst-bulk",
          revision: 1,
        }),
        now,
        now,
      )
      .run();

    await workspaceMatchStatement(db, {
      tenantId: "tenant-bulk",
      objectId: "obj-match-1",
      entityId: "entity-match-1",
      evidenceIds: [],
      criteria: ["test"],
      eventId: "event-match-1",
      matchedAt: now,
      score: 40,
      matchStatus: "complete",
      lastEvaluatedAt: now,
      onConflict: "update",
    }).run();

    const match = await db
      .prepare(
        "SELECT match_status,last_evaluated_at FROM workspace_matches WHERE tenant_id=? AND object_id=? AND entity_id=?",
      )
      .bind("tenant-bulk", "obj-match-1", "entity-match-1")
      .first<{ match_status: string; last_evaluated_at: string }>();
    expect(match?.match_status).toBe("complete");
    expect(match?.last_evaluated_at).toBe(now);
  });

  it("remembers duplicates across pages via payload.seenIds", async () => {
    const unique = { observable: "cross-page-dup.example" };
    const inputs = Array.from({ length: 101 }, (_, i) =>
      i === 100 ? unique : i === 0 ? unique : { observable: `page-item-${i}.example` },
    );
    // page 0: index 0 unique + 99 others; page 1 (offset 100): index 100 is duplicate of index 0
    const submitted = await submitBulk(
      db,
      archive,
      principal,
      inputs,
      "bulk-pages-" + crypto.randomUUID(),
      "corr-bulk-pages",
    );
    const row = await db
      .prepare("SELECT data FROM pipeline_jobs WHERE id=?")
      .bind(submitted.job_id)
      .first<{ data: string }>();
    const job = JSON.parse(row!.data) as PipelineJob;
    await processBulk({ DB: db, ARCHIVE: archive } as unknown as AppEnv, job);

    const page2 = await db
      .prepare(
        "SELECT data FROM pipeline_jobs WHERE id=? AND status='queued'",
      )
      .bind(submitted.job_id + ":page:100")
      .first<{ data: string }>();
    expect(page2).toBeTruthy();
    const child = JSON.parse(page2!.data) as PipelineJob;
    expect(Array.isArray(child.payload.seenIds)).toBe(true);
    expect((child.payload.seenIds as string[]).length).toBeGreaterThan(0);
    await processBulk({ DB: db, ARCHIVE: archive } as unknown as AppEnv, child);

    const last = await db
      .prepare("SELECT result FROM pipeline_jobs WHERE id=?")
      .bind(submitted.job_id + ":page:100")
      .first<{ result: string }>();
    const shape = JSON.parse(last!.result) as {
      processed: number;
      accepted: number;
      duplicates: number;
      rejected: number;
    };
    expect(shape.processed).toBe(101);
    expect(shape.duplicates).toBe(1);
    expect(shape.accepted).toBe(100);
    expect(shape.rejected).toBe(0);
  });
});
