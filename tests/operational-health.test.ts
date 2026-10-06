import { beforeAll, afterAll, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readdirSync, readFileSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import {
  operationalAlerts,
  operationalReport,
  recordMaintenanceHeartbeat,
} from "../packages/observability/src/health";
import type { OperationalReport } from "../packages/schemas/src/operations";
import type { AppEnv } from "../apps/api/src/env";
import { Repository } from "../packages/database/src/repository";
import { makeJob } from "../workers/ingest/pipeline";
import { digest } from "../packages/intel/src/normalise";
import { app } from "../apps/api/src/index";
let mf: Miniflare, db: D1Database, env: AppEnv;
const now = Date.now(),
  at = new Date(now).toISOString(),
  old = new Date(now - 86400000).toISOString();
const base: Omit<OperationalReport, "status" | "alerts"> = {
  schema_version: "1.0",
  checked_at: at,
  heartbeat: at,
  archive_heartbeat: at,
  feeds: [],
  jobs: [],
  outbox: { pending: 0, oldest: null },
  usage: { calls: 0, input_tokens: 0, daily_limit: 1000 },
  integrations: [],
};
it("healthy services do not create alerts", () =>
  expect(operationalAlerts(base, now)).toEqual([]));
it("stale services, failed jobs, budget and connector errors have explicit thresholds", () => {
  const alerts = operationalAlerts(
    {
      ...base,
      heartbeat: old,
      archive_heartbeat: null,
      feeds: [
        {
          id: "mitre",
          name: "MITRE",
          configured: true,
          enabled: 1,
          status: "healthy",
          last_sync: old,
          next_sync: null,
          records_processed: 1,
          records_added: 1,
          records_updated: 0,
          errors: 0,
        },
      ],
      jobs: [
        {
          stage: "enrich",
          status: "failed",
          count: 1,
          oldest: old,
          stale_result_count: 1,
        },
      ],
      outbox: { pending: 1, oldest: old },
      usage: { ...base.usage, calls: 800 },
      integrations: [
        {
          connector_id: "connector",
          last_poll_at: old,
          last_success_at: null,
          status: "error",
          error_type: "HTTPError",
          version: "1",
        },
      ],
    },
    now,
  );
  expect(alerts.map((a) => a.code)).toEqual(
    expect.arrayContaining([
      "SCHEDULER_STALE",
      "ARCHIVE_HEARTBEAT_STALE",
      "FEED_STALE",
      "PIPELINE_FAILED",
      "PIPELINE_STATE_CONFLICT",
      "OUTBOX_LAG",
      "CLASSIFICATION_BUDGET",
      "CONNECTOR_ERROR",
      "CONNECTOR_STALE",
    ]),
  );
});
it("missing required credentials warn, disabled optional sources do not", () => {
  const feed = {
    name: "Source",
    configured: false,
    enabled: 1,
    status: "disabled",
    last_sync: null,
    next_sync: null,
    records_processed: 0,
    records_added: 0,
    records_updated: 0,
    errors: 0,
  };
  expect(
    operationalAlerts(
      {
        ...base,
        feeds: [
          { ...feed, id: "threatfox" },
          { ...feed, id: "otx" },
        ],
      },
      now,
    ),
  ).toEqual([
    {
      code: "FEED_NOT_CONFIGURED",
      severity: "warning",
      subject: "threatfox",
      message: expect.any(String),
    },
  ]);
});
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
    r2Buckets: ["ARCHIVE"],
  });
  db = await mf.getD1Database("DB");
  env = {
    DB: db,
    WEB_ORIGIN: "https://web.test",
    ARCHIVE: await mf.getR2Bucket("ARCHIVE"),
  } as unknown as AppEnv;
  for (const file of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + file, "utf8"),
    ))
      await db.prepare(sql).run();
  for (const tenant of ["ops-a", "ops-b"]) {
    await db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind(tenant, tenant, at)
      .run();
  }
  for (const [key, tenant, scopes] of [
    ["ops-read", "ops-a", ["ops:read"]],
    ["ops-write", "ops-a", ["integration:write"]],
    ["ops-other", "ops-b", ["ops:read", "integration:write"]],
    ["intel-read", "ops-a", ["intel:read"]],
  ] as const) {
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,'ops-analyst',?,?,?,?)",
      )
      .bind(key, tenant, key, await digest(key), JSON.stringify(scopes), at)
      .run();
  }
});
afterAll(async () => {
  await mf?.dispose();
});
const call = (path: string, key: string, body?: unknown) =>
  app.request(
    path,
    {
      method: body ? "POST" : "GET",
      headers: {
        Authorization: "Bearer " + key,
        "Content-Type": "application/json",
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    },
    env,
  );
it("operational queries isolate tenant jobs and connector identities", async () => {
  const repo = new Repository(db);
  await repo.enqueue(makeJob("enrich", "global"));
  await repo.enqueue(makeJob("enrich", "private-a", "ops-a"));
  await repo.enqueue(makeJob("enrich", "private-b", "ops-b"));
  await recordMaintenanceHeartbeat(env);
  const connector = "11111111-1111-4111-8111-111111111111";
  expect(
    (
      await call("/v1/integrations/opencti/heartbeat", "ops-other", {
        connector_id: connector,
        status: "ok",
        version: "1",
      })
    ).status,
  ).toBe(200);
  const report = await operationalReport(env, "ops-a");
  expect(report.jobs.reduce((n, j) => n + j.count, 0)).toBe(2);
  expect(report.outbox.pending).toBe(2);
  expect(report.integrations).toEqual([]);
  expect(report.heartbeat).not.toBeNull();
  expect(report.archive_heartbeat).not.toBeNull();
  expect((await call("/v1/ops/status", "ops-read")).status).toBe(200);
  expect((await call("/v1/ops/status", "intel-read")).status).toBe(403);
  expect((await call("/v1/ops/status", "ops-write")).status).toBe(403);
});
it("heartbeat write scope cannot change intelligence; errors preserve last success", async () => {
  const path = "/v1/integrations/opencti/heartbeat",
    connector_id = "22222222-2222-4222-8222-222222222222";
  const input = { connector_id, status: "ok", version: "1" };
  expect((await call(path, "ops-read", input)).status).toBe(403);
  expect((await call(path, "ops-write", input)).status).toBe(200);
  expect(
    (
      await call(path, "ops-write", {
        ...input,
        status: "error",
        error_type: "HTTPError",
      })
    ).status,
  ).toBe(200);
  const report = await operationalReport(env, "ops-a");
  expect(report.integrations[0]?.last_success_at).not.toBeNull();
  expect(report.alerts.some((a) => a.code === "CONNECTOR_ERROR")).toBe(true);
  expect(
    (
      await call(path, "ops-write", {
        ...input,
        error_type: "https://secret.example/token",
      })
    ).status,
  ).toBe(400);
  expect(
    (await call("/v1/assess", "ops-write", { observable: "example.com" }))
      .status,
  ).toBe(403);
});
