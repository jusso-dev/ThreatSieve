import { migrationStatements } from "../packages/database/src/migrations";
import { beforeAll, afterAll, describe, it, expect, vi } from "vitest";
import { z } from "zod";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { Repository } from "../packages/database/src/repository";
import { PublicFeed, stixRecord } from "../packages/intel/src/feeds";
import { ingestRecord } from "../packages/intel/src/ingest";
import { normalise, digest } from "../packages/intel/src/normalise";
import { buildEvidenceBundle } from "../packages/attack/src/candidates";
import { ClefDecisionEngine } from "../packages/clef/src/index";
import { RecordedTransport } from "./helpers";
import { app } from "../apps/api/src/index";
import { authenticate } from "../packages/auth/src/index";
import type { Evidence, Principal } from "../packages/schemas/src/index";
import { queueFeedSync, normalizeFeedChunk } from "../workers/feed-sync/index";
import { makeJob } from "../workers/ingest/pipeline";
import type { AppEnv } from "../apps/api/src/env";
import { submitBulk } from "../workers/ingest/submission";
import { exportAssessment } from "../workers/export/index";
let mf: Miniflare;
let db: D1Database;
let repo: Repository;
const principal: Principal = {
  tenantId: "tenant-a",
  userId: "analyst-a",
  keyId: "key-a",
  scopes: ["admin"],
  kind: "key",
};
const provenance = {
  sourceId: "mitre",
  sourceName: "MITRE ATT&CK",
  retrievedAt: new Date().toISOString(),
  redistributable: true,
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
  repo = new Repository(db);
  for (const name of readdirSync("migrations").sort()) {
    const sql = readFileSync("migrations/" + name, "utf8");
    for (const statement of migrationStatements(sql))
      await db.prepare(statement).run();
  }
  await db.batch([
    db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind("tenant-a", "A", new Date().toISOString()),
    db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind("tenant-b", "B", new Date().toISOString()),
  ]);
  await db
    .prepare(
      "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(
      "key-a",
      "tenant-a",
      "analyst-a",
      "Test",
      await digest("test-only-key"),
      JSON.stringify(["admin"]),
      new Date().toISOString(),
    )
    .run();
});
afterAll(async () => {
  await mf?.dispose();
});
describe("first complete indicator-to-assessment pipeline", () => {
  it("imports ATT&CK and ThreatFox, deduplicates, generates bounded candidates and persists probabilities", async () => {
    const objects = [
      {
        type: "malware",
        id: "malware--11111111-1111-4111-8111-111111111111",
        name: "TestRAT",
        description: "Synthetic malware for offline integration testing",
      },
      {
        type: "attack-pattern",
        id: "attack-pattern--22222222-2222-4222-8222-222222222222",
        name: "Web Protocols",
        description: "Web protocol communication",
        external_references: [
          { source_name: "mitre-attack", external_id: "T1071.001" },
        ],
      },
      {
        type: "relationship",
        id: "relationship--33333333-3333-4333-8333-333333333333",
        source_ref: "malware--11111111-1111-4111-8111-111111111111",
        target_ref: "attack-pattern--22222222-2222-4222-8222-222222222222",
        relationship_type: "uses",
      },
    ];
    for (const raw of objects)
      for (const r of await stixRecord(raw, provenance))
        await ingestRecord(repo, r);
    const provider = new PublicFeed("threatfox", "ThreatFox", repo);
    const raw = {
      id: "synthetic-1",
      ioc: "C2.EXAMPLE.test",
      ioc_type: "domain",
      threat_type: "botnet_cc",
      malware_printable: "TestRAT",
      confidence_level: 95,
      first_seen: "2026-10-04 13:36:27 UTC",
      last_seen: null,
    };
    for (let i = 0; i < 2; i++)
      for (const r of await provider.normalize(raw))
        await ingestRecord(repo, r);
    const observable = await normalise(raw.ioc);
    expect((await repo.evidence(observable.id)).length).toBe(1);
    let bundle = await buildEvidenceBundle(repo, "tenant-a", observable.id);
    expect(bundle.attackCandidates.map((c) => c.externalId)).toContain(
      "T1071.001",
    );
    const transport = new RecordedTransport();
    const engine = new ClefDecisionEngine(transport);
    const initial = await engine.classifyObservable(bundle, [
      { id: "threatfox", independent_group: "abuse.ch", reliability: 0.9 },
    ]);
    expect(initial.attack).toEqual([]);
    expect(initial.runs).toHaveLength(2);
    expect(initial.actors).toEqual([]);
    const ev: Evidence = {
      id: "telemetry-a",
      observableId: observable.id,
      type: "telemetry",
      sourceId: "customer",
      provenance: {
        ...provenance,
        sourceId: "customer",
        sourceName: "Customer telemetry",
        redistributable: false,
      },
      data: {
        description:
          "Process sent recurring HTTP POST beacons with command responses.",
        malicious: true,
      },
      confidence: 0.95,
      createdAt: new Date().toISOString(),
      observedAt: new Date().toISOString(),
      behavioural: true,
    };
    await db
      .prepare("INSERT INTO customer_observations VALUES(?,?,?,?,?,?)")
      .bind(
        ev.id,
        "tenant-a",
        observable.id,
        JSON.stringify(ev),
        ev.createdAt,
        0,
      )
      .run();
    bundle = await buildEvidenceBundle(repo, "tenant-a", observable.id);
    const a = await engine.classifyObservable(bundle, [
      { id: "threatfox", independent_group: "abuse.ch", reliability: 0.9 },
    ]);
    expect(a.attack[0]?.techniqueId).toBe("T1071.001");
    expect(a.attack[0]?.mappingType).toBe("model_inferred");
    await repo.saveAssessment("tenant-a", a, ["test-key"]);
    expect(
      (await repo.assessment("tenant-a", a.assessment_id))?.runs[0]?.raw,
    ).toBeDefined();
    expect(await repo.assessment("tenant-b", a.assessment_id)).toBeNull();
    expect(
      (
        await buildEvidenceBundle(repo, "tenant-b", observable.id)
      ).evidence.some((e) => e.id === "telemetry-a"),
    ).toBe(false);
    const env = { DB: db, WEB_ORIGIN: "https://web.test" };
    const request = await app.request(
      "/v1/assessments/" + a.assessment_id,
      { headers: { Authorization: "Bearer test-only-key" } },
      env,
    );
    expect(request.status).toBe(200);
    const response = (await request.json()) as { assessment_id: string };
    expect(response.assessment_id).toBe(a.assessment_id);
    await repo.feedback(
      principal,
      a.assessment_id,
      "confirmed",
      "assessment",
      null,
      "Reviewed source evidence",
      "test-correlation",
    );
    expect((await repo.assessment("tenant-a", a.assessment_id))?.status).toBe(
      "confirmed",
    );
    expect(await repo.cached("tenant-a", "test-key")).toBeNull();
    expect(
      (
        await db
          .prepare("SELECT COUNT(*) AS n FROM audit_events WHERE tenant_id=?")
          .bind("tenant-a")
          .first<{ n: number }>()
      )?.n,
    ).toBe(1);
  });
  it("hides private submitted observables across tenants", async () => {
    const o = await normalise("private-customer.test");
    await repo.putObservable(
      o,
      {
        sourceId: "customer",
        sourceName: "Private telemetry",
        retrievedAt: new Date().toISOString(),
        redistributable: false,
      },
      "tenant-a",
    );
    expect(await repo.visible("tenant-a", o.id)).toBe(true);
    expect(await repo.visible("tenant-b", o.id)).toBe(false);
    const req = new Request("https://api.test/v1/me", {
      headers: { Authorization: "Bearer test-only-key" },
    });
    expect((await authenticate(db, req)).tenantId).toBe("tenant-a");
  });
  it("enforces scope and validates graph depth and upload bounds", async () => {
    const env = { DB: db, WEB_ORIGIN: "https://web.test" };
    expect((await app.request("/v1/assessments", {}, env)).status).toBe(401);
    expect(
      (
        await app.request(
          "/v1/graph/id?depth=40",
          { headers: { Authorization: "Bearer test-only-key" } },
          env,
        )
      ).status,
    ).toBe(400);
  });
  it("prevents cross-tenant API reads and analyst mutations, even with guessed IDs", async () => {
    const o = await normalise("private-customer.test");
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
      )
      .bind(
        "key-b",
        "tenant-b",
        "analyst-b",
        "B key",
        await digest("tenant-b-test-key"),
        JSON.stringify(["admin"]),
        new Date().toISOString(),
      )
      .run();
    const env = { DB: db, WEB_ORIGIN: "https://web.test" };
    const headers = {
      Authorization: "Bearer tenant-b-test-key",
      "Content-Type": "application/json",
    };
    const assessment = (await repo.assessments("tenant-a"))[0]!;
    for (const path of [
      "/v1/assessments/" + assessment.assessment_id,
      "/v1/observables/" + o.id,
      "/v1/graph/" + o.id,
    ])
      expect((await app.request(path, { headers }, env)).status).toBe(404);
    expect(
      (
        await app.request(
          "/v1/assessments/" + assessment.assessment_id + "/confirm",
          {
            method: "POST",
            headers,
            body: JSON.stringify({
              reason: "Attempted cross-tenant confirmation",
            }),
          },
          env,
        )
      ).status,
    ).toBe(404);
    const search = await app.request(
      "/v1/search?q=private-customer",
      { headers },
      env,
    );
    expect(((await search.json()) as { data: unknown[] }).data).toEqual([]);
    await expect(
      repo.feedback(
        { ...principal, tenantId: "tenant-b" },
        assessment.assessment_id,
        "rejected",
        "assessment",
        null,
        "Wrong tenant",
        "corr",
      ),
    ).rejects.toThrow("not found");
  });
  it("atomically records outbox work, leases one consumer and preserves distinct downstream jobs", async () => {
    const job = {
      jobId: "job-lease-a",
      tenantId: "tenant-a",
      entityId: "observable-a",
      stage: "enrich" as const,
      attempt: 0,
      createdAt: new Date().toISOString(),
      correlationId: "corr-a",
      payload: {},
    };
    await repo.enqueue(job);
    await repo.enqueue(job);
    expect(
      (
        await db
          .prepare("SELECT COUNT(*) AS n FROM outbox WHERE id=?")
          .bind(job.jobId)
          .first<{ n: number }>()
      )?.n,
    ).toBe(1);
    expect(await repo.claim(job)).toBe(true);
    expect(await repo.claim(job)).toBe(false);
    await repo.finish(
      job,
      { done: true },
      { ...job, jobId: job.jobId + ":correlate", stage: "correlate" },
    );
    expect((await repo.job("tenant-a", job.jobId))?.status).toBe("complete");
    expect(await repo.job("tenant-b", job.jobId)).toBeNull();
    expect((await repo.queuedMessage(job.jobId + ":correlate"))?.entityId).toBe(
      "observable-a",
    );
  });
  it("revokes sessions with their API key and enforces least privilege", async () => {
    const key = "reader-test-key";
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
      )
      .bind(
        "reader-key",
        "tenant-a",
        "analyst-a",
        "Read only",
        await digest(key),
        JSON.stringify(["intel:read"]),
        new Date().toISOString(),
      )
      .run();
    const env = { DB: db, WEB_ORIGIN: "https://web.test" };
    expect(
      (
        await app.request(
          "/v1/assess",
          {
            method: "POST",
            headers: {
              Authorization: "Bearer " + key,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ observable: "example.test" }),
          },
          env,
        )
      ).status,
    ).toBe(403);
    await db
      .prepare("INSERT INTO sessions VALUES(?,?,?,?,?)")
      .bind(
        await digest("session-secret"),
        "tenant-a",
        "analyst-a",
        "reader-key",
        new Date(Date.now() + 60000).toISOString(),
      )
      .run();
    expect(
      (
        await authenticate(
          db,
          new Request("https://api.test", {
            headers: { cookie: "ts_session=session-secret" },
          }),
        )
      ).tenantId,
    ).toBe("tenant-a");
    await db
      .prepare("UPDATE api_keys SET revoked_at=? WHERE id=?")
      .bind(new Date().toISOString(), "reader-key")
      .run();
    await expect(
      authenticate(
        db,
        new Request("https://api.test", {
          headers: { cookie: "ts_session=session-secret" },
        }),
      ),
    ).rejects.toThrow("invalid or expired");
  });
  it("saves analyst overrides separately and rejects invented entity selections", async () => {
    const a = (await repo.assessments("tenant-a"))[0]!;
    const updated = await repo.feedback(
      principal,
      a.assessment_id,
      "modified",
      "malicious",
      "benign",
      "Verified legitimate infrastructure",
      "override-corr",
    );
    expect(updated.effective_classification).toBe("benign");
    expect(updated.malicious).toEqual(a.malicious);
    expect(updated.analyst_decision?.value).toBe("benign");
    await expect(
      repo.feedback(
        principal,
        a.assessment_id,
        "modified",
        "actors",
        ["invented-actor"],
        "Unsupported actor",
        "override-corr",
      ),
    ).rejects.toThrow("existing intelligence");
  });
});

it("reserves a single feed sync and pages large archived chunks without losing records", async () => {
  const archive = await mf.getR2Bucket("ARCHIVE");
  // Miniflare exposes RPC proxy types; production handlers receive the equivalent native bindings.
  const env = { DB: db, ARCHIVE: archive } as unknown as AppEnv;
  const first = await queueFeedSync(env, "feodo");
  const second = await queueFeedSync(env, "feodo");
  expect(second.jobId).toBe(first.jobId);
  const key = "test/feodo-chunk.json";
  await archive.put(
    key,
    JSON.stringify(
      Array.from({ length: 11 }, (_, i) => ({
        ip_address: "192.0.2." + (100 + i),
        port: 443,
        malware: "SyntheticPagingBot",
        first_seen: "2026-10-01T00:00:00Z",
      })),
    ),
  );
  const job = makeJob(
    "normalise",
    "feodo",
    undefined,
    { feedId: "feodo", feedChunk: key, rawKey: key, feedJobId: first.jobId },
    first.correlationId,
  );
  await repo.enqueue(job);
  await normalizeFeedChunk(env, job);
  expect(
    await repo.observable((await normalise("192.0.2.109")).id),
  ).not.toBeNull();
  expect(await repo.observable((await normalise("192.0.2.110")).id)).toBeNull();
  const page = await repo.queuedMessage(job.jobId + ":page:10");
  expect(page).not.toBeNull();
  await normalizeFeedChunk(env, page!);
  expect(
    await repo.observable((await normalise("192.0.2.110")).id),
  ).not.toBeNull();
  await normalizeFeedChunk(env, page!);
  expect(
    (
      await db
        .prepare(
          "SELECT COUNT(*) AS n FROM observables WHERE normalized_value LIKE ?",
        )
        .bind("192.0.2.1%")
        .first<{ n: number }>()
    )?.n,
  ).toBe(11);
});
it("paginates assessments with identical timestamps without omitting records", async () => {
  const a = (await repo.assessments("tenant-a"))[0]!;
  const created_at = "2099-01-01T00:00:00.000Z";
  for (const suffix of ["a", "b"])
    await repo.saveAssessment(
      "tenant-a",
      { ...a, assessment_id: "cursor-test-" + suffix, created_at },
      [],
    );
  const first = await repo.assessments("tenant-a", 1);
  expect(first[0]?.assessment_id).toBe("cursor-test-a");
  const second = await repo.assessments(
    "tenant-a",
    1,
    btoa(JSON.stringify([created_at, first[0]!.assessment_id])),
  );
  expect(second[0]?.assessment_id).toBe("cursor-test-b");
});

it("deduplicates concurrent upload requests, rejects body conflicts, and scopes keys to tenants", async () => {
  const archive = await mf.getR2Bucket("ARCHIVE");
  const inputs = [{ observable: "batch-security.example" }];
  const results = await Promise.all([
    submitBulk(db, archive, principal, inputs, "batch-retry", "one"),
    submitBulk(db, archive, principal, inputs, "batch-retry", "two"),
  ]);
  expect(results[0]!.job_id).toBe(results[1]!.job_id);
  expect(
    (
      await db
        .prepare("SELECT COUNT(*) AS n FROM pipeline_jobs WHERE id=?")
        .bind(results[0]!.job_id)
        .first<{ n: number }>()
    )?.n,
  ).toBe(1);
  expect(
    (
      await db
        .prepare(
          "SELECT COUNT(*) AS n FROM audit_events WHERE entity_id=? AND action='bulk.import'",
        )
        .bind(results[0]!.job_id)
        .first<{ n: number }>()
    )?.n,
  ).toBe(1);
  await expect(
    submitBulk(
      db,
      archive,
      principal,
      [{ observable: "different.example" }],
      "batch-retry",
      "conflict",
    ),
  ).rejects.toMatchObject({ status: 409 });
  const other = await submitBulk(
    db,
    archive,
    { ...principal, tenantId: "tenant-b" },
    inputs,
    "batch-retry",
    "other",
  );
  expect(other.job_id).not.toBe(results[0]!.job_id);
  const objects = await archive.list({ prefix: "uploads/" });
  expect(objects.objects.length).toBe(2);
});
it("retains unresolved reviews and pages beyond the first 50 tenant assessments", async () => {
  const base = (await repo.assessments("tenant-a"))[0]!;
  for (let i = 0; i < 53; i++)
    await repo.saveAssessment(
      "tenant-a",
      {
        ...base,
        assessment_id: "review-page-" + i,
        revision: 0,
        status: "needs-investigation",
        human_review: true,
        created_at: new Date(Date.UTC(2098, 0, 1, 0, 0, i)).toISOString(),
      },
      [],
    );
  const first = await repo.assessments("tenant-a", 50, undefined, {
    view: "review",
    q: "test",
  });
  expect(first.length).toBe(50);
  const last = first.at(-1)!;
  const second = await repo.assessments(
    "tenant-a",
    50,
    btoa(JSON.stringify([last.created_at, last.assessment_id])),
    { view: "review", q: "test" },
  );
  expect(second.length).toBeGreaterThan(0);
  expect(new Set([...first, ...second].map((a) => a.assessment_id)).size).toBe(
    first.length + second.length,
  );
  expect(
    (await repo.assessmentSummary("tenant-a")).summary.review,
  ).toBeGreaterThanOrEqual(53);
  expect(
    await repo.assessments("tenant-b", 50, undefined, { view: "review" }),
  ).toHaveLength(0);
  await expect(
    repo.assessments("tenant-a", 50, "invalid"),
  ).rejects.toMatchObject({ status: 400 });
});
it("exports immutable corrections, synchronizes review metadata and rejects concurrent stale feedback", async () => {
  const archive = await mf.getR2Bucket("ARCHIVE");
  const base = (await repo.assessments("tenant-a"))[0]!;
  const a = {
    ...base,
    assessment_id: "export-revision-test",
    revision: 0,
    updated_at: undefined,
    created_at: new Date().toISOString(),
    status: "pending" as const,
    effective_classification: undefined,
  };
  await repo.saveAssessment("tenant-a", a, []);
  const first = await exportAssessment(
    { DB: db, ARCHIVE: archive },
    "tenant-a",
    a.assessment_id,
  );
  const snapshot = await repo.assessment("tenant-a", a.assessment_id);
  const read = vi.spyOn(repo, "assessment").mockResolvedValue(snapshot);
  const edits = await Promise.allSettled([
    repo.feedback(
      principal,
      a.assessment_id,
      "modified",
      "malicious",
      "benign",
      "Confirmed legitimate infrastructure",
      "edit-one",
    ),
    repo.feedback(
      principal,
      a.assessment_id,
      "modified",
      "malicious",
      "suspicious",
      "Conflicting analyst update",
      "edit-two",
    ),
  ]);
  read.mockRestore();
  expect(edits.filter((result) => result.status === "fulfilled")).toHaveLength(
    1,
  );
  expect(edits.filter((result) => result.status === "rejected")).toHaveLength(
    1,
  );
  const corrected = (await repo.assessment("tenant-a", a.assessment_id))!;
  expect(corrected.revision).toBe(1);
  await expect(
    repo.feedback(
      principal,
      a.assessment_id,
      "confirmed",
      "assessment",
      undefined,
      "Stale browser decision",
      "stale",
      0,
    ),
  ).rejects.toMatchObject({ code: "ASSESSMENT_CHANGED", status: 409 });
  const second = await exportAssessment(
    { DB: db, ARCHIVE: archive },
    "tenant-a",
    a.assessment_id,
  );
  expect(second.id).not.toBe(first.id);
  expect(
    await exportAssessment(
      { DB: db, ARCHIVE: archive },
      "tenant-a",
      a.assessment_id,
    ),
  ).toEqual(second);
  const bundle = z
    .object({
      objects: z.array(
        z.object({
          type: z.string(),
          x_threatsieve_classification: z
            .object({ classification: z.string() })
            .optional(),
        }),
      ),
    })
    .parse(await (await archive.get(second.r2_key))!.json());
  expect(
    bundle.objects.find((o) => o.type === "indicator")
      ?.x_threatsieve_classification?.classification,
  ).toBe(corrected.effective_classification);
  const pending = await repo.queuedMessage(
    "export:" + a.assessment_id + ":revision:1",
  );
  expect(pending?.tenantId).toBe("tenant-a");
  await repo.feedback(
    principal,
    a.assessment_id,
    "confirmed",
    "assessment",
    undefined,
    "Verified corrected decision",
    "confirmed",
  );
  expect(
    (
      await db
        .prepare(
          "SELECT human_review FROM assessments WHERE tenant_id=? AND id=?",
        )
        .bind("tenant-a", a.assessment_id)
        .first<{ human_review: number }>()
    )?.human_review,
  ).toBe(0);
  await expect(
    exportAssessment({ DB: db, ARCHIVE: archive }, "tenant-b", a.assessment_id),
  ).rejects.toThrow("not found");
});

it("requires an API key and a trusted browser Origin for development-only legacy sessions", async () => {
  const env = {
    DB: db,
    WEB_ORIGIN: "https://web.test",
    APP_ENV: "development",
  };
  const rejected = await app.request(
    "/v1/session",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer test-only-key",
        Origin: "https://untrusted.test",
      },
    },
    env,
  );
  expect(rejected.status).toBe(403);
  const permitted = await app.request(
    "/v1/session",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer test-only-key",
        Origin: "https://web.test",
      },
    },
    env,
  );
  expect(permitted.status).toBe(200);
  const cookie = permitted.headers.get("set-cookie")!;
  expect(cookie).toContain("HttpOnly");
  expect(cookie).toContain("SameSite=Strict");
  expect(
    (
      await app.request(
        "/v1/session",
        {
          method: "POST",
          headers: {
            Cookie: cookie.split(";")[0]!,
            Origin: "https://web.test",
          },
        },
        env,
      )
    ).status,
  ).toBe(401);
});

it("excludes tenant-rejected relationships from candidates without changing other tenants' intelligence", async () => {
  const observable = await normalise("c2.example.test");
  const before = await buildEvidenceBundle(repo, "tenant-a", observable.id);
  const technique = before.attackCandidates.find(
    (c) => c.externalId === "T1071.001",
  )!;
  const relation = before.relationships.find(
    (r) => r.targetEntityId === technique.id,
  )!;
  await repo.db
    .prepare("INSERT INTO classification_cache VALUES(?,?,?,?)")
    .bind("tenant-a", "reject-test-cache", "unused", new Date().toISOString())
    .run();
  const response = await app.request(
    "/v1/relationships/" + relation.id + "/reject",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer test-only-key",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        reason: "Source relationship does not apply to this investigation",
      }),
    },
    { DB: db, WEB_ORIGIN: "https://web.test" },
  );
  expect(response.status).toBe(200);
  const after = await buildEvidenceBundle(repo, "tenant-a", observable.id);
  expect(after.attackCandidates.some((c) => c.id === technique.id)).toBe(false);
  expect(after.evidenceVersion).not.toBe(before.evidenceVersion);
  expect(
    (
      await buildEvidenceBundle(repo, "tenant-b", observable.id)
    ).attackCandidates.some((c) => c.id === technique.id),
  ).toBe(true);
  expect(
    await repo.db
      .prepare("SELECT cache_key FROM classification_cache WHERE tenant_id=?")
      .bind("tenant-a")
      .first(),
  ).toBeNull();
});

it("does not include hidden neighboring observables or their edges in another tenant's evidence bundle", async () => {
  const observable = await normalise("c2.example.test");
  const privateObservable = await normalise("private-customer.test");
  const now = new Date().toISOString();
  await repo.putRelationship({
    id: "private-neighbor-edge",
    sourceEntityId: observable.id,
    targetEntityId: privateObservable.id,
    relationshipType: "resolves-to",
    assertionType: "source_claimed",
    confidence: 0.9,
    sourceIds: ["mitre"],
    provenance,
    createdAt: now,
    updatedAt: now,
  });
  const owner = await buildEvidenceBundle(repo, "tenant-a", observable.id);
  expect(
    owner.relationships.some((r) => r.id === "private-neighbor-edge"),
  ).toBe(true);
  expect(
    (await repo.edges(observable.id, 80, "tenant-b")).some(
      (r) => r.id === "private-neighbor-edge",
    ),
  ).toBe(false);
  const other = await buildEvidenceBundle(repo, "tenant-b", observable.id);
  expect(JSON.stringify(other)).not.toContain(privateObservable.id);
  await expect(
    buildEvidenceBundle(repo, "tenant-b", privateObservable.id),
  ).rejects.toMatchObject({ status: 404 });
});
