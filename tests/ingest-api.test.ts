import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Miniflare } from "miniflare";
import { migratedDatabase } from "./hub-fixtures";
import { app } from "../apps/api/src/index";
import { digest } from "../packages/intel/src/normalise";
import { consume } from "../workers/ingest/pipeline";
import { ingestOpenApi } from "../packages/ingest/src/openapi";
import type { AppEnv } from "../apps/api/src/env";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions inspect arbitrary JSON
type Json = any;
let mf: Miniflare;
let db: D1Database;
let env: AppEnv;
const keys = {
  a: "test-ingest-a",
  aRead: "test-ingest-a-reader",
  aEdr: "test-ingest-a-edr",
  limited: "test-ingest-c-limited",
  b: "test-ingest-b",
};
const ctx = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
} as unknown as ExecutionContext;
const fixture = (name: string) =>
  readFileSync("tests/fixtures/ingest/" + name, "utf8");

async function post(
  body: unknown,
  {
    key = keys.a,
    type = "application/json",
    headers = {},
    environment = env,
  }: {
    key?: string;
    type?: string;
    headers?: Record<string, string>;
    environment?: AppEnv;
  } = {},
) {
  const response = await app.request(
    "/v1/ingest",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + key,
        "Content-Type": type,
        "cf-connecting-ip": "192.0.2.10",
        ...headers,
      },
      body: typeof body === "string" ? body : JSON.stringify(body),
    },
    environment,
    ctx,
  );
  return {
    status: response.status,
    headers: response.headers,
    json: (await response.json()) as Json,
  };
}
async function get(path: string, key = keys.a) {
  const response = await app.request(
    path,
    { headers: { Authorization: "Bearer " + key } },
    env,
    ctx,
  );
  return { status: response.status, json: (await response.json()) as Json };
}
/** Delivers the batch's queued job the way the Queues consumer would. */
async function drain(batchId: string) {
  const row = await db
    .prepare("SELECT data FROM pipeline_jobs WHERE id=?")
    .bind("ingest:" + batchId)
    .first<{ data: string }>();
  expect(row).not.toBeNull();
  const ack = vi.fn();
  await consume(
    {
      queue: "intel-ingest",
      messages: [
        {
          id: "m",
          timestamp: new Date(),
          attempts: 1,
          body: JSON.parse(row!.data),
          ack,
          retry: vi.fn(),
        },
      ],
      ackAll: vi.fn(),
      retryAll: vi.fn(),
    } as unknown as MessageBatch<unknown>,
    env,
  );
  expect(ack).toHaveBeenCalled();
}
const alert = (extra: Record<string, unknown> = {}) => ({
  type: "alert",
  external_id: "alert-1",
  title: "Beacon to known C2",
  summary: "EDR saw a beacon.",
  severity: "high",
  source: {
    name: "EDR",
    vendor: "Example EDR",
    url: "https://edr.example/alerts/1",
  },
  published_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
  indicators: [{ type: "domain", value: "c2[.]evil.example", confidence: 90 }],
  attack_techniques: ["T1071.001"],
  tlp: "amber",
  raw: { vendor_alert_id: 1, nested: { kept: ["as", "is"] } },
  ...extra,
});

beforeAll(async () => {
  let bucket: R2Bucket;
  ({ mf, db, bucket } = await migratedDatabase());
  vi.stubGlobal("fetch", () => {
    throw new Error("Ingest must not make network requests");
  });
  const queue = {
    send: async () => undefined,
    sendBatch: async () => undefined,
  };
  env = {
    DB: db,
    ARCHIVE: bucket,
    ...Object.fromEntries(
      [
        "INGEST",
        "OPERATIONS",
        "NORMALISE",
        "ENRICH",
        "CORRELATE",
        "CLASSIFY",
        "EXPORT",
      ].map((q) => [q + "_QUEUE", queue]),
    ),
    WEB_ORIGIN: "https://web.test",
    INGEST_RATE_LIMIT: "1000",
  } as unknown as AppEnv;
  const now = new Date().toISOString();
  await db
    .prepare(
      "INSERT INTO tenants(id,name,created_at) VALUES('tenant-a','A',?),('tenant-b','B',?),('tenant-c','C',?)",
    )
    .bind(now, now, now)
    .run();
  for (const [id, tenant, key, scopes, sources] of [
    ["key-a", "tenant-a", keys.a, ["ingest:write", "ingest:read"], null],
    ["key-a-read", "tenant-a", keys.aRead, ["intel:read"], null],
    ["key-a-edr", "tenant-a", keys.aEdr, ["ingest:write"], ["EDR"]],
    // Its own tenant, so the per-tenant counter starts empty.
    ["key-c-limited", "tenant-c", keys.limited, ["ingest:write"], null],
    ["key-b", "tenant-b", keys.b, ["ingest:write", "ingest:read"], null],
  ] as const)
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at,ingest_sources) VALUES(?,?,?,?,?,?,?,?)",
      )
      .bind(
        id,
        tenant,
        "user-" + id,
        id,
        await digest(key),
        JSON.stringify(scopes),
        now,
        sources ? JSON.stringify(sources) : null,
      )
      .run();
});
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
});

describe("authentication and limits", () => {
  it("requires an API key with the ingest scopes", async () => {
    const anonymous = await app.request(
      "/v1/ingest",
      { method: "POST", body: "{}" },
      env,
      ctx,
    );
    expect(anonymous.status).toBe(401);
    expect((await post(alert(), { key: keys.aRead })).status).toBe(403);
    expect(
      (await get("/v1/ingest/inb_00000000000000000000000000000000", keys.aEdr))
        .status,
    ).toBe(403);
  });

  it("limits a source-scoped key to its sources", async () => {
    const other = await post(alert({ source: { name: "Firewall" } }), {
      key: keys.aEdr,
    });
    expect(other.status).toBe(400);
    expect(other.json.error.items[0].issues).toEqual([
      {
        path: ["source", "name"],
        message: "This API key may not submit items for this source",
      },
    ]);
    expect(
      (await post(alert({ external_id: "edr-scoped" }), { key: keys.aEdr }))
        .status,
    ).toBe(201);
  });

  it("rejects oversized bodies, too many items and unknown media types", async () => {
    const huge = JSON.stringify(
      alert({ summary: "x".repeat(5 * 1024 * 1024) }),
    );
    const tooLarge = await post(huge);
    expect(tooLarge.status).toBe(413);
    expect(tooLarge.json.error.code).toBe("PAYLOAD_TOO_LARGE");
    const declared = await post("{}", {
      headers: { "Content-Length": String(6 * 1024 * 1024) },
    });
    expect(declared.status).toBe(413);
    const many = await post(
      Array.from({ length: 501 }, (_, i) => alert({ external_id: "m" + i })),
    );
    expect(many.status).toBe(413);
    expect(many.json.error.code).toBe("TOO_MANY_ITEMS");
    const envelope = await post({
      format: "native",
      items: Array.from({ length: 501 }, () => ({})),
    });
    expect(envelope.status).toBe(413);
    expect((await post("<xml/>", { type: "application/xml" })).status).toBe(
      415,
    );
    const deep = await post("[".repeat(100) + "]".repeat(100));
    expect(deep.status).toBe(400);
    const invalid = await post("{not json");
    expect(invalid.status).toBe(400);
    expect(invalid.json.error.code).toBe("INVALID_JSON");
  });

  it("rate limits per key with its own bucket", async () => {
    const limited = { ...env, INGEST_RATE_LIMIT: "2" } as AppEnv;
    for (let i = 0; i < 2; i++)
      expect(
        (
          await post(alert({ external_id: "rl-" + i }), {
            key: keys.limited,
            environment: limited,
          })
        ).status,
      ).toBe(201);
    const blocked = await post(alert({ external_id: "rl-3" }), {
      key: keys.limited,
      environment: limited,
    });
    expect(blocked.status).toBe(429);
    expect(blocked.json.error.code).toBe("RATE_LIMITED");
    expect(Number(blocked.headers.get("Retry-After"))).toBeGreaterThan(0);
  });
});

describe("single items", () => {
  it("stores a native alert synchronously and shows how it was normalised", async () => {
    const created = await post(alert());
    expect(created.status).toBe(201);
    expect(created.json).toMatchObject({ status: "created", revision: 1 });
    expect(created.json.id).toMatch(/^ing_[a-f0-9]{40}$/);
    const stored = await get("/v1/ingest/" + created.json.id);
    expect(stored.status).toBe(200);
    expect(stored.json.item).toMatchObject({
      type: "alert",
      format: "native",
      severity: "high",
      severity_source: "provided",
      tlp: "amber",
      indicators: [
        {
          type: "domain",
          value: "c2.evil.example",
          display_value: "c2[.]evil[.]example",
          confidence: 90,
        },
      ],
    });
    expect(stored.json.normalisation.changes).toContainEqual({
      path: ["indicators", 0, "value"],
      from: "c2[.]evil.example",
      to: "c2.evil.example",
    });
    expect(stored.json.raw).toEqual({
      vendor_alert_id: 1,
      nested: { kept: ["as", "is"] },
    });
    const audit = await db
      .prepare(
        "SELECT actor_id,source_ip,data FROM audit_events WHERE tenant_id='tenant-a' AND action='ingest.item' AND entity_id=?",
      )
      .bind(created.json.id)
      .first<{ actor_id: string; source_ip: string; data: string }>();
    expect(audit).toMatchObject({
      actor_id: "user-key-a",
      source_ip: "192.0.2.10",
    });
    expect(JSON.parse(audit!.data)).toMatchObject({
      key_id: "key-a",
      source: "EDR",
      external_id: "alert-1",
      outcome: "created",
    });
  });

  it("deduplicates on source and external ID: repeats update, identical or older copies do not", async () => {
    const first = await post(alert({ external_id: "dedupe-1" }));
    expect(first.status).toBe(201);
    // Source names compare case- and whitespace-insensitively, so this
    // updates the stored item (its display name changed) rather than adding one.
    const renamed = alert({
      external_id: "dedupe-1",
      source: { name: " edr " },
    });
    const same = await post(renamed);
    expect(same).toMatchObject({
      status: 200,
      json: { id: first.json.id, status: "updated", revision: 2 },
    });
    const unchanged = await post(renamed);
    expect(unchanged).toMatchObject({
      status: 200,
      json: { status: "unchanged" },
    });
    const updated = await post(
      alert({
        external_id: "dedupe-1",
        severity: "critical",
        updated_at: "2026-10-02T00:00:00Z",
      }),
    );
    expect(updated).toMatchObject({
      status: 200,
      json: { id: first.json.id, status: "updated" },
    });
    const stale = await post(
      alert({
        external_id: "dedupe-1",
        severity: "low",
        updated_at: "2026-09-01T00:00:00Z",
      }),
    );
    expect(stale.json.status).toBe("unchanged");
    const stored = await get("/v1/ingest/" + first.json.id);
    expect(stored.json.item.severity).toBe("critical");
    const rows = await db
      .prepare(
        "SELECT COUNT(*) AS n FROM ingest_items WHERE tenant_id='tenant-a' AND external_id='dedupe-1'",
      )
      .first<number>("n");
    expect(rows).toBe(1);
  });

  it("returns 400 with every field error for an invalid item", async () => {
    const bad = await post({
      type: "alert",
      title: "x",
      source: { name: "EDR" },
      severity: "urgent",
      indicators: [{ type: "ipv4", value: "1.2.3" }],
    });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toMatchObject({
      code: "VALIDATION_ERROR",
      items: [{ index: 0 }],
    });
    expect(
      bad.json.error.items[0].issues.map((i: { path: unknown[] }) => i.path),
    ).toEqual([["severity"]]);
    const value = await post({
      type: "alert",
      title: "x",
      source: { name: "EDR" },
      indicators: [{ type: "ipv4", value: "1.2.3" }],
    });
    expect(value.json.error.items[0].issues).toEqual([
      { path: ["indicators", 0, "value"], message: "Invalid IPv4 address" },
    ]);
  });

  it("keeps originals over 256 KiB in R2 and returns them on read", async () => {
    const big = { blob: "y".repeat(300 * 1024) };
    const created = await post(alert({ external_id: "big-raw", raw: big }));
    expect(created.status).toBe(201);
    const row = await db
      .prepare(
        "SELECT raw,raw_key FROM ingest_items WHERE tenant_id='tenant-a' AND id=?",
      )
      .bind(created.json.id)
      .first<{ raw: string | null; raw_key: string }>();
    expect(row?.raw).toBeNull();
    expect(row?.raw_key).toMatch(/^ingest\/raw\/tenant-a\//);
    expect((await get("/v1/ingest/" + created.json.id)).json.raw).toEqual(big);
  });
});

describe("batches", () => {
  it("accepts good items, reports bad ones per item, and stores asynchronously", async () => {
    const response = await post([
      alert({ external_id: "batch-1" }),
      { type: "alert", title: "missing source" },
      alert({
        external_id: "batch-2",
        indicators: [{ type: "url", value: "ftp://x.example" }],
      }),
      alert({ external_id: "batch-3" }),
      alert({ external_id: "batch-1", title: "Second copy wins" }),
    ]);
    expect(response.status).toBe(202);
    expect(response.json).toMatchObject({
      status: "queued",
      received: 5,
      accepted: 3,
      rejected: 2,
      deduplicated: 1,
    });
    expect(
      response.json.errors.map(
        (e: { index: number; issues: { path: unknown[] }[] }) => [
          e.index,
          e.issues[0]!.path,
        ],
      ),
    ).toEqual([
      [1, ["source"]],
      [2, ["indicators", 0, "value"]],
    ]);
    const batchId = response.json.ingest_id as string;
    expect(response.json.status_url).toBe("/v1/ingest/" + batchId);
    expect((await get("/v1/ingest/" + batchId)).json.status).toBe("queued");
    await drain(batchId);
    const batch = await get("/v1/ingest/" + batchId);
    expect(batch.json).toMatchObject({
      status: "complete",
      created: 2,
      updated: 0,
      unchanged: 0,
      deduplicated: 1,
    });
    expect(
      batch.json.items.map((i: { index: number; status: string }) => [
        i.index,
        i.status,
      ]),
    ).toEqual([
      [0, "superseded"],
      [3, "created"],
      [4, "created"],
    ]);
    const winner = batch.json.items.find(
      (i: { index: number }) => i.index === 4,
    );
    expect((await get("/v1/ingest/" + winner.id)).json.item.title).toBe(
      "Second copy wins",
    );
    // A second delivery of the same message is harmless.
    await drain(batchId);
    expect((await get("/v1/ingest/" + batchId)).json.created).toBe(2);
    const audit = await db
      .prepare(
        "SELECT data FROM audit_events WHERE action='ingest.batch' AND entity_id=?",
      )
      .bind(batchId)
      .first<string>("data");
    expect(JSON.parse(audit!)).toMatchObject({
      key_id: "key-a",
      format: "native",
      received: 5,
      accepted: 3,
      rejected: 2,
      sources: ["EDR"],
    });
  });

  it("returns 400 when no item in a batch is valid", async () => {
    const response = await post([{ type: "alert" }, { title: "x" }]);
    expect(response.status).toBe(400);
    expect(
      response.json.error.items.map((i: { index: number }) => i.index),
    ).toEqual([0, 1]);
  });

  it("replays the first response for a repeated Idempotency-Key and rejects a changed body", async () => {
    const body = [
      alert({ external_id: "idem-1" }),
      alert({ external_id: "idem-2" }),
    ];
    const headers = { "Idempotency-Key": "retry-123" };
    const first = await post(body, { headers });
    const second = await post(body, { headers });
    expect(second.status).toBe(202);
    expect(second.json).toEqual(first.json);
    expect(first.headers.get("Idempotent-Replayed")).toBeNull();
    expect(second.headers.get("Idempotent-Replayed")).toBe("true");
    const batches = await db
      .prepare(
        "SELECT COUNT(*) AS n FROM ingest_batches WHERE tenant_id='tenant-a' AND id=?",
      )
      .bind(first.json.ingest_id)
      .first<number>("n");
    expect(batches).toBe(1);
    const conflict = await post([alert({ external_id: "idem-3" })], {
      headers,
    });
    expect(conflict.status).toBe(409);
    expect(conflict.json.error.code).toBe("IDEMPOTENCY_CONFLICT");
    // Keys are per tenant.
    expect((await post(body, { key: keys.b, headers })).status).toBe(202);
  });
});

describe("formats", () => {
  it("detects STIX from Content-Type and queues the bundle", async () => {
    const response = await post(fixture("stix-poisonivy.json"), {
      type: "application/stix+json;version=2.1",
    });
    expect(response.status).toBe(202);
    expect(response.json).toMatchObject({
      format: "stix",
      received: 32,
      accepted: 31,
      rejected: 1,
    });
    expect(response.json.errors[0]).toMatchObject({
      source_ref: "indicator--4e4c4ad7-4909-456a-b6fa-e24a6f682a40",
      external_id: "indicator--4e4c4ad7-4909-456a-b6fa-e24a6f682a40",
    });
    await drain(response.json.ingest_id);
    const batch = await get("/v1/ingest/" + response.json.ingest_id);
    expect(batch.json.created).toBe(31);
    const report = batch.json.items.find((i: { external_id: string }) =>
      i.external_id.startsWith("report--"),
    );
    const stored = await get("/v1/ingest/" + report.id);
    expect(stored.json.item).toMatchObject({
      type: "advisory",
      format: "stix",
      source: { name: "FireEye, Inc." },
    });
    expect(stored.json.raw.type).toBe("report");
  });

  it("detects CSAF and OSV documents and stores single documents synchronously", async () => {
    const csaf = await post(fixture("csaf-rhsa-2021_5217.json"), {
      type: "application/csaf+json",
    });
    expect(csaf.status).toBe(201);
    expect(csaf.json.item).toMatchObject({
      format: "csaf",
      external_id: "RHSA-2021:5217",
      severity: "high",
      tlp: "clear",
    });
    const osv = await post(fixture("osv-GHSA-c2qf-rxjj-qqgw.json"), {
      type: "application/osv+json",
    });
    expect(osv.status).toBe(201);
    expect(osv.json.item).toMatchObject({
      format: "osv",
      cvss: { score: 7.5 },
    });
    const again = await post(fixture("osv-GHSA-c2qf-rxjj-qqgw.json"), {
      type: "application/osv+json",
    });
    expect(again).toMatchObject({
      status: 200,
      json: { id: osv.json.id, status: "unchanged" },
    });
    const stored = await get("/v1/ingest/" + csaf.json.id);
    expect(stored.json.raw).toEqual(
      JSON.parse(fixture("csaf-rhsa-2021_5217.json")),
    );
  });

  it("reads the format and a default TLP from a JSON envelope", async () => {
    const response = await post({
      format: "osv",
      default_tlp: "clear",
      items: [JSON.parse(fixture("osv-PYSEC-2023-74.json")), { id: "broken" }],
    });
    expect(response.status).toBe(202);
    expect(response.json).toMatchObject({
      format: "osv",
      accepted: 1,
      rejected: 1,
    });
    expect(response.json.errors[0]).toMatchObject({
      index: 1,
      document: 1,
      source_ref: "broken",
    });
    await drain(response.json.ingest_id);
    const id = response.json.items[0].id;
    expect((await get("/v1/ingest/" + id)).json.item).toMatchObject({
      tlp: "clear",
      tlp_source: "default",
    });
    const bad = await post({ format: "yaml", items: [{}] });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe("VALIDATION_ERROR");
  });
});

describe("TLP and tenancy", () => {
  it("never exposes TLP:RED or AMBER items to another tenant", async () => {
    const red = await post(alert({ external_id: "red-1", tlp: "red" }));
    const amber = await post(
      alert({ external_id: "amber-1", tlp: "amber+strict" }),
    );
    for (const id of [red.json.id, amber.json.id]) {
      expect((await get("/v1/ingest/" + id)).status).toBe(200);
      expect((await get("/v1/ingest/" + id, keys.b)).status).toBe(404);
    }
    // The same source and external ID in another tenant is a separate record.
    const other = await post(
      alert({ external_id: "red-1", tlp: "red", title: "Tenant B copy" }),
      { key: keys.b },
    );
    expect(other.status).toBe(201);
    expect(other.json.id).not.toBe(red.json.id);
    expect((await get("/v1/ingest/" + red.json.id)).json.item.title).toBe(
      "Beacon to known C2",
    );
  });

  it("treats unmarked items as TLP:AMBER", async () => {
    const { tlp: _, ...unmarked } = alert({ external_id: "unmarked-1" });
    const created = await post(unmarked);
    expect(created.json.item).toMatchObject({
      tlp: "amber",
      tlp_source: "default",
    });
  });
});

describe("metrics and contract", () => {
  it("counts received, accepted, rejected and deduplicated items per day", async () => {
    const metrics = await get("/v1/ingest/metrics?days=1");
    expect(metrics.status).toBe(200);
    const [today] = metrics.json.data;
    expect(today.day).toBe(new Date().toISOString().slice(0, 10));
    expect(today.received).toBeGreaterThan(0);
    expect(today.rejected).toBeGreaterThan(0);
    expect(today.deduplicated).toBeGreaterThan(0);
    expect(today.received).toBe(today.accepted + today.rejected);
  });

  it("publishes the OpenAPI document without authentication, matching docs/openapi/ingest.json", async () => {
    const response = await app.request("/openapi/ingest.json", {}, env, ctx);
    expect(response.status).toBe(200);
    const spec = (await response.json()) as ReturnType<typeof ingestOpenApi>;
    expect(spec.openapi).toBe("3.1.0");
    expect(Object.keys(spec.paths)).toEqual([
      "/v1/ingest",
      "/v1/ingest/{id}",
      "/v1/ingest/metrics",
    ]);
    expect(
      Object.keys(spec.paths["/v1/ingest"].post.requestBody.content),
    ).toEqual(
      expect.arrayContaining([
        "application/json",
        "application/stix+json",
        "application/csaf+json",
        "application/osv+json",
      ]),
    );
    // Regenerate with `pnpm openapi:ingest` when this fails.
    expect(
      JSON.parse(readFileSync("docs/openapi/ingest.json", "utf8")),
    ).toEqual(spec);
  });
});
