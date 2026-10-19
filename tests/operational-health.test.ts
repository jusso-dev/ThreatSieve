import { beforeAll, afterAll, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readdirSync, readFileSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import {
  GLOBAL_JOBS_SQL,
  OUTBOX_DISPATCHED_SQL,
  OUTBOX_PENDING_SQL,
  STALE_RESULTS_SQL,
  TENANT_JOBS_SQL,
  operationalJobs,
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
  outbox: { pending: 0, oldest: null, last_dispatch: null },
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
          latest: old,
          stale_result_count: 1,
        },
      ],
      outbox: { pending: 1, oldest: old, last_dispatch: null },
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
it("operational job summary seeks live work instead of scanning job history", async () => {
  // Regression: /v1/ops/status read every global pipeline job ever created and
  // crossed the production probe's 30 second timeout as the table grew.
  const tenant = "ops-b",
    since = new Date(now - 86400000).toISOString(),
    ancient = new Date(now - 30 * 86400000).toISOString(),
    recent = new Date(now - 60000).toISOString();
  const insert = db.prepare(
    "INSERT INTO pipeline_jobs(id,tenant_id,entity_id,stage,status,data,result,created_at,updated_at) VALUES(?,?,'e',?,?,'{}',?,?,?)",
  );
  const rows: [string | null, string, string, string | null, string][] = [
    [null, "normalise", "complete", "{}", ancient],
    [null, "normalise", "complete", "{}", recent],
    [null, "normalise", "queued", null, recent],
    [null, "classify", "running", "{}", recent],
    [null, "classify", "failed", null, ancient],
    [tenant, "export", "complete", "{}", ancient],
    [tenant, "export", "queued", null, ancient],
    ["ops-a", "export", "queued", null, recent],
  ];
  await db.batch(
    rows.map(([t, stage, status, result, when], i) =>
      insert.bind("plan-" + i, t, stage, status, result, when, when),
    ),
  );
  const results = await operationalJobs(db, tenant, since);
  const mine = results.filter((r) =>
    ["normalise", "classify", "export"].includes(r.stage),
  );
  expect(mine).toEqual([
    {
      stage: "classify",
      status: "failed",
      count: 1,
      oldest: ancient,
      latest: ancient,
      stale_result_count: 0,
    },
    {
      stage: "classify",
      status: "running",
      count: 1,
      oldest: recent,
      latest: recent,
      stale_result_count: 1,
    },
    {
      stage: "export",
      status: "queued",
      count: 1,
      oldest: ancient,
      latest: ancient,
      stale_result_count: 0,
    },
    {
      stage: "normalise",
      status: "complete",
      count: 1,
      oldest: recent,
      latest: recent,
      stale_result_count: 0,
    },
    {
      stage: "normalise",
      status: "queued",
      count: 1,
      oldest: recent,
      latest: recent,
      stale_result_count: 0,
    },
  ]);
  for (const [sql, args] of [
    [TENANT_JOBS_SQL, [tenant, since]],
    [GLOBAL_JOBS_SQL, [since]],
  ] as const) {
    const plan = await db
      .prepare("EXPLAIN QUERY PLAN " + sql)
      .bind(...args)
      .all<{ detail: string }>();
    const details = plan.results.map((r) => r.detail);
    expect(details.some((d) => d.startsWith("SEARCH pipeline_jobs"))).toBe(
      true,
    );
    expect(details.filter((d) => /^SCAN pipeline_jobs/.test(d))).toEqual([]);
    // A bare tenant seek reads the whole append-only history for that scope.
    expect(details.filter((d) => /\((tenant_id|status)=\?\)$/.test(d))).toEqual(
      [],
    );
    // Row lookups walk each job's data JSON; a day of feed-sync jobs made that
    // slower than the probe timeout, so the summary must stay index-only.
    expect(
      details.filter(
        (d) =>
          d.startsWith("SEARCH pipeline_jobs") && !/COVERING INDEX/.test(d),
      ),
    ).toEqual([]);
  }
  const stalePlan = await db
    .prepare("EXPLAIN QUERY PLAN " + STALE_RESULTS_SQL)
    .bind(tenant)
    .all<{ detail: string }>();
  const staleDetails = stalePlan.results
    .map((r) => r.detail)
    .filter((d) => d.includes("pipeline_jobs"));
  expect(staleDetails.length).toBeGreaterThan(0);
  expect(
    staleDetails.filter(
      (d) =>
        !/^SEARCH pipeline_jobs USING (COVERING )?INDEX jobs_unfinished_result /.test(
          d,
        ),
    ),
  ).toEqual([]);
});

const job = (
  stage: string,
  status: string,
  createdAgo: number,
  latestAgo: number | null = createdAgo,
): OperationalReport["jobs"][number] => ({
  stage,
  status,
  count: 1,
  oldest: new Date(now - createdAgo).toISOString(),
  latest: latestAgo === null ? null : new Date(now - latestAgo).toISOString(),
  stale_result_count: 0,
});
const minutes = (n: number) => n * 60000;
it("a post-sync backlog that is still progressing only warns", () => {
  const alerts = operationalAlerts(
    {
      ...base,
      jobs: [
        job("classify", "queued", minutes(120)),
        job("classify", "complete", minutes(200), minutes(1)),
      ],
    },
    now,
  );
  expect(alerts).toEqual([
    {
      code: "PIPELINE_BACKLOG",
      severity: "warning",
      subject: "classify",
      message: expect.any(String),
    },
  ]);
});
it("a running claim counts as progress for its stage", () => {
  const alerts = operationalAlerts(
    {
      ...base,
      jobs: [
        job("enrich", "queued", minutes(40)),
        job("enrich", "running", minutes(30), minutes(2)),
      ],
    },
    now,
  );
  expect(alerts.map((a) => [a.code, a.severity, a.subject])).toEqual([
    ["PIPELINE_BACKLOG", "warning", "enrich"],
  ]);
});
it("a stage with pending work and no recent progress is critical", () => {
  for (const jobs of [
    [job("classify", "queued", minutes(20))],
    [
      job("classify", "queued", minutes(20)),
      job("classify", "complete", minutes(90), minutes(30)),
    ],
    // Progress on another stage does not count.
    [
      job("classify", "queued", minutes(20)),
      job("enrich", "complete", minutes(5), minutes(1)),
    ],
  ])
    expect(
      operationalAlerts({ ...base, jobs }, now).filter(
        (a) => a.severity === "critical",
      ),
    ).toEqual([
      {
        code: "PIPELINE_LAG",
        severity: "critical",
        subject: "classify",
        message: expect.stringContaining("no progress"),
      },
    ]);
});
it("a backlog older than one feed cycle is critical despite progress", () => {
  expect(
    operationalAlerts(
      {
        ...base,
        jobs: [
          job("correlate", "queued", minutes(7 * 60)),
          job("correlate", "complete", minutes(60), minutes(1)),
        ],
      },
      now,
    ),
  ).toEqual([
    {
      code: "PIPELINE_LAG",
      severity: "critical",
      subject: "correlate",
      message: "Backlog has not drained within one feed cycle.",
    },
  ]);
});
it("raises one lag alert per stage when queued and running rows both lag", () => {
  const alerts = operationalAlerts(
    {
      ...base,
      jobs: [
        job("normalise", "queued", minutes(40)),
        job("normalise", "running", minutes(50), minutes(45)),
      ],
    },
    now,
  );
  expect(alerts.map((a) => [a.code, a.subject])).toEqual([
    ["PIPELINE_LAG", "normalise"],
  ]);
});
it("a publishing outbox warns, a stalled one is critical", () => {
  const pending = (oldestAgo: number, dispatchAgo: number | null) =>
    operationalAlerts(
      {
        ...base,
        outbox: {
          pending: 5,
          oldest: new Date(now - oldestAgo).toISOString(),
          last_dispatch:
            dispatchAgo === null
              ? null
              : new Date(now - dispatchAgo).toISOString(),
        },
      },
      now,
    ).map((a) => [a.code, a.severity]);
  expect(pending(minutes(5), null)).toEqual([]);
  expect(pending(minutes(30), minutes(1))).toEqual([
    ["OUTBOX_BACKLOG", "warning"],
  ]);
  expect(pending(minutes(30), minutes(11))).toEqual([
    ["OUTBOX_LAG", "critical"],
  ]);
  expect(pending(minutes(30), null)).toEqual([["OUTBOX_LAG", "critical"]]);
  expect(pending(minutes(7 * 60), minutes(1))).toEqual([
    ["OUTBOX_LAG", "critical"],
  ]);
});
it("the report carries stage progress and the last outbox publication", async () => {
  const repo = new Repository(db);
  const queued = makeJob("export", "progress-entity", "ops-a");
  await repo.enqueue(queued);
  const at = new Date().toISOString();
  await db
    .prepare(
      "UPDATE outbox SET dispatched_at=? WHERE id=(SELECT id FROM outbox WHERE dispatched_at IS NULL ORDER BY created_at LIMIT 1)",
    )
    .bind(at)
    .run();
  const report = await operationalReport(env, "ops-a");
  const row = report.jobs.find(
    (j) => j.stage === "export" && j.status === "queued",
  );
  expect(row?.latest).toEqual(expect.any(String));
  expect(report.outbox.last_dispatch).toBe(at);
});

it("future or invalid progress timestamps cannot conceal a stalled stage", () => {
  for (const latest of [new Date(now + 60000).toISOString(), "invalid"]) {
    const alerts = operationalAlerts(
      {
        ...base,
        jobs: [
          {
            stage: "classify",
            status: "queued",
            count: 1,
            oldest: new Date(now - 20 * 60000).toISOString(),
            latest: null,
            stale_result_count: 0,
          },
          {
            stage: "classify",
            status: "complete",
            count: 1,
            oldest: at,
            latest,
            stale_result_count: 0,
          },
        ],
      },
      now,
    );
    expect(alerts).toContainEqual(
      expect.objectContaining({ code: "PIPELINE_LAG", severity: "critical" }),
    );
  }
});
it("another tenant's recent outbox dispatch does not mask a tenant's publication stall", async () => {
  const repo = new Repository(db);
  const mine = makeJob("enrich", "scoped-old", "ops-a");
  const theirs = makeJob("enrich", "scoped-recent", "ops-b");
  await repo.enqueue(mine);
  await repo.enqueue(theirs);
  await db
    .prepare("UPDATE outbox SET created_at=? WHERE id=?")
    .bind(old, mine.jobId)
    .run();
  // Earlier tests may have dispatched global or own entries. Reset only this
  // isolated database's publication signal to establish the cross-tenant case.
  await db
    .prepare(
      "UPDATE outbox SET dispatched_at=? WHERE dispatched_at IS NOT NULL",
    )
    .bind(old)
    .run();
  await db
    .prepare("UPDATE outbox SET dispatched_at=? WHERE id=?")
    .bind(new Date().toISOString(), theirs.jobId)
    .run();
  const report = await operationalReport(env, "ops-a");
  expect(report.outbox.last_dispatch).toBeNull();
  expect(report.alerts).toContainEqual(
    expect.objectContaining({ code: "OUTBOX_LAG", severity: "critical" }),
  );
});
it("outbox health reads seek the outbox before joining jobs", async () => {
  // Regression: driving from pipeline_jobs read every global job to probe the
  // outbox, 2.9M rows per /v1/ops/status call in production.
  for (const [sql, args] of [
    [OUTBOX_PENDING_SQL, ["ops-a"]],
    [OUTBOX_DISPATCHED_SQL, [new Date(now).toISOString(), "ops-a"]],
  ] as const) {
    const plan = await db
      .prepare("EXPLAIN QUERY PLAN " + sql)
      .bind(...args)
      .all<{ detail: string }>();
    expect(plan.results.map((r) => r.detail)).toEqual([
      expect.stringMatching(
        /^SEARCH o USING .*INDEX outbox_\w+ \(dispatched_at[=>]/,
      ),
      expect.stringMatching(
        /^SEARCH p USING .*INDEX sqlite_autoindex_pipeline_jobs_1 \(id=\?\)/,
      ),
    ]);
  }
});
