import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Miniflare } from "miniflare";
import { hubFetch, migratedDatabase } from "./hub-fixtures";
import { app } from "../apps/api/src/index";
import { Repository } from "../packages/database/src/repository";
import { digest, entityId, normalise } from "../packages/intel/src/normalise";
import { ingestRecord } from "../packages/intel/src/ingest";
import { AdditionalFeed } from "../packages/intel/src/additional-feeds";
import { importIpToAsn } from "../packages/intel/src/network";
import { importEpss, syncNvdPage } from "../packages/intel/src/cve";
import { clearDatasetCache } from "../packages/intel/src/datasets";
import { LookupResponseSchema } from "../packages/schemas/src/lookup";
import { JobSchema, type Evidence } from "../packages/schemas/src/index";
import { processJob } from "../workers/ingest/pipeline";
import {
  FINAL_ATTEMPT,
  processLookupJob,
} from "../packages/intel/src/source-lookups";
import type { AppEnv } from "../apps/api/src/env";

let mf: Miniflare;
let db: D1Database;
let bucket: R2Bucket;
const fake = hubFetch();
const now = new Date("2099-01-04T00:00:00.000Z");
const keys = {
  reader: "test-lookup-reader",
  writer: "test-assess-only",
  other: "test-tenant-b-reader",
};
const env = (extra: Record<string, unknown> = {}) => ({
  DB: db,
  ARCHIVE: bucket,
  WEB_ORIGIN: "https://web.test",
  // Lookups must never reach Workers AI.
  AI: {
    run: () => {
      throw new Error("Workers AI must not be called by lookup");
    },
  },
  ...extra,
});
const deferred: Promise<unknown>[] = [];
const ctx = {
  waitUntil: (p: Promise<unknown>) => void deferred.push(p),
  passThroughOnException: () => undefined,
  props: {},
} as unknown as ExecutionContext;
async function lookup(
  body: unknown,
  options: { key?: string; env?: Record<string, unknown> } = {},
) {
  return app.request(
    "/v1/lookup",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + (options.key ?? keys.reader),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    },
    env(options.env),
    ctx,
  );
}
/** Runs queued lookup refresh jobs the way the enrich queue consumer does. */
async function runLookupJobs(extra: Record<string, unknown> = {}) {
  await Promise.allSettled(deferred.splice(0));
  const rows = await db
    .prepare(
      "SELECT data FROM pipeline_jobs WHERE stage='enrich' AND status='queued' AND json_extract(data,'$.payload.mode')='source-lookup' ORDER BY created_at",
    )
    .all<{ data: string }>();
  const repo = new Repository(db);
  for (const row of rows.results) {
    const job = JobSchema.parse(JSON.parse(row.data));
    expect(await repo.claim(job)).toBe(true);
    await processJob(env(extra) as unknown as AppEnv, job);
  }
  return rows.results.length;
}
/** Counts D1 statements prepared through the binding. */
function countingDb() {
  let statements = 0;
  const proxy = new Proxy(db, {
    get(target, property) {
      if (property === "prepare")
        return (sql: string) => {
          statements++;
          return target.prepare(sql);
        };
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { proxy, count: () => statements };
}
async function errorCode(response: Response) {
  return ((await response.json()) as { error: { code: string } }).error.code;
}
async function results(body: unknown, options?: Parameters<typeof lookup>[1]) {
  const response = await lookup(body, options);
  expect(response.status).toBe(200);
  return LookupResponseSchema.parse(await response.json());
}
const feedEvidence = (
  sourceId: string,
  id: string,
  data: Evidence["data"],
  observedAt: string,
): Evidence => ({
  id,
  type: "feed",
  sourceId,
  data,
  provenance: {
    sourceId,
    sourceName: sourceId,
    retrievedAt: "2099-01-03T00:00:00.000Z",
    redistributable: false,
    sourceUrl: "https://" + sourceId + ".example.test/" + id,
  },
  confidence: 0.9,
  createdAt: "2099-01-03T00:00:00.000Z",
  observedAt,
  behavioural: false,
});

beforeAll(async () => {
  ({ mf, db, bucket } = await migratedDatabase());
  vi.stubGlobal("fetch", fake.request);
  const at = now.toISOString();
  await db.batch([
    db
      .prepare(
        "INSERT INTO tenants(id,name,created_at) VALUES('tenant-a','A',?)",
      )
      .bind(at),
    db
      .prepare(
        "INSERT INTO tenants(id,name,created_at) VALUES('tenant-b','B',?)",
      )
      .bind(at),
    db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES('key-read','tenant-a','user-a','Foiled',?,?,?)",
      )
      .bind(await digest(keys.reader), JSON.stringify(["intel:read"]), at),
    db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES('key-write','tenant-a','user-a','Assess',?,?,?)",
      )
      .bind(
        await digest(keys.writer),
        JSON.stringify(["assessment:write"]),
        at,
      ),
    db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES('key-b','tenant-b','user-b','B',?,?,?)",
      )
      .bind(await digest(keys.other), JSON.stringify(["intel:read"]), at),
  ]);
  const repo = new Repository(db);
  // A ThreatFox-style malicious IP linked to a MITRE group.
  const ip = await normalise("203.0.113.7");
  await ingestRecord(repo, {
    observable: { value: "203.0.113.7", type: "ipv4" },
    provenance: {
      sourceId: "threatfox",
      sourceName: "ThreatFox",
      retrievedAt: at,
      redistributable: false,
    },
    relationships: [],
    evidence: [
      feedEvidence(
        "threatfox",
        "ev-tf-1",
        { malicious: true, role: "c2", tags: ["bruteforce", "c2"] },
        "2099-01-02T00:00:00.000Z",
      ),
    ],
  });
  const mitre = {
    sourceId: "mitre",
    sourceName: "MITRE ATT&CK",
    retrievedAt: at,
    redistributable: true,
  };
  await repo.putEntity({
    id: "intrusion-set--example",
    type: "threat-actor",
    name: "Example Group",
    description: "Synthetic",
    aliases: ["Example Alias"],
    externalId: "G9999",
    data: {},
    provenance: mitre,
  });
  await repo.putRelationship({
    id: "rel-example-indicates",
    sourceEntityId: ip.id,
    targetEntityId: "intrusion-set--example",
    relationshipType: "INDICATES",
    assertionType: "source_claimed",
    confidence: 0.6,
    sourceIds: ["mitre"],
    provenance: mitre,
    createdAt: at,
    updatedAt: at,
  });
  // Tenant B's private submission must stay invisible to tenant A.
  await repo.putObservable(
    await normalise("private-b.example"),
    {
      sourceId: "upload",
      sourceName: "Upload",
      retrievedAt: at,
      redistributable: false,
    },
    "tenant-b",
  );
  // CISA KEV through the real adapter.
  const kev = new AdditionalFeed("cisa-kev", "CISA KEV", repo);
  for (const record of await kev.normalize({
    cveID: "CVE-2099-0001",
    vendorProject: "Example",
    product: "Demo App",
    vulnerabilityName: "Example Demo App Path Traversal",
    dateAdded: "2099-01-02",
    shortDescription: "Synthetic KEV entry.",
    requiredAction: "Apply updates.",
    dueDate: "2099-01-23",
    knownRansomwareCampaignUse: "Unknown",
  }))
    await ingestRecord(repo, record);
  await db
    .prepare("UPDATE sources SET last_sync=? WHERE id='cisa-kev'")
    .bind(at)
    .run();
  await importIpToAsn({ DB: db, ARCHIVE: bucket }, fake.request, now);
  await importEpss({ DB: db, ARCHIVE: bucket }, fake.request, now);
  await syncNvdPage(
    { DB: db, ARCHIVE: bucket },
    fake.request,
    { cursor: null },
    now,
  );
}, 120000);
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
});

describe("POST /v1/lookup", () => {
  it("requires an intel:read key and validates the request", async () => {
    const anonymous = await app.request(
      "/v1/lookup",
      {
        method: "POST",
        body: "{}",
        headers: { "Content-Type": "application/json" },
      },
      env(),
      ctx,
    );
    expect(anonymous.status).toBe(401);
    const forbidden = await lookup(
      { observables: [{ type: "ipv4", value: "203.0.113.7" }] },
      { key: keys.writer },
    );
    expect(forbidden.status).toBe(403);
    expect(await errorCode(forbidden)).toBe("FORBIDDEN");
    const tooMany = await lookup({
      observables: Array.from({ length: 501 }, (_, i) => ({
        type: "domain",
        value: "host-" + i + ".example",
      })),
    });
    expect(tooMany.status).toBe(413);
    expect(await errorCode(tooMany)).toBe("TOO_MANY_OBSERVABLES");
    const badType = await lookup({
      observables: [{ type: "email", value: "a@b.example" }],
    });
    expect(badType.status).toBe(400);
    expect(await errorCode(badType)).toBe("VALIDATION_ERROR");
  });

  it("returns reputation, network, relationships and licensed provenance for an IP", async () => {
    const body = await results({
      observables: [{ type: "ipv4", value: "203.0.113.7" }],
    });
    const [result] = body.results;
    expect(result).toMatchObject({
      type: "ipv4",
      value: "203.0.113.7",
      found: true,
      entity_id: (await normalise("203.0.113.7")).id,
      ttl_seconds: 21600,
      pending_sources: [],
      reputation: {
        classification: "malicious",
        scanner: null,
        tags: ["bruteforce", "c2"],
      },
      network: {
        asn: 64500,
        as_org: "EXAMPLE-AS Example Hosting",
        prefix: "203.0.113.0/24",
        country: "AU",
      },
      cve: null,
      relationships: [
        {
          type: "indicates",
          direction: "outgoing",
          assertion: "source_claimed",
          confidence: 60,
          source_id: "mitre",
          target: {
            id: "intrusion-set--example",
            type: "threat-actor",
            name: "Example Group",
            external_ids: { mitre: "G9999" },
          },
        },
      ],
    });
    expect(result!.reputation!.score).toBeGreaterThan(0);
    expect(result!.reputation!.confidence).toBeGreaterThan(0);
    expect(result!.sources.map((s) => s.source_id)).toEqual([
      "iptoasn",
      "mitre",
      "threatfox",
    ]);
    expect(
      result!.sources.find((s) => s.source_id === "threatfox"),
    ).toMatchObject({
      name: "ThreatFox",
      redistributable: false,
      commercial_use: false,
      reliability: 0.85,
      first_seen: "2099-01-02T00:00:00.000Z",
      source_url: "https://threatfox.example.test/ev-tf-1",
    });
    expect(
      result!.sources.find((s) => s.source_id === "iptoasn"),
    ).toMatchObject({
      license: "Public Domain Dedication and License (PDDL) 1.0",
      redistributable: true,
      commercial_use: true,
    });
    expect(result!.sources.find((s) => s.source_id === "mitre")).toMatchObject({
      redistributable: true,
      commercial_use: true,
    });
  });

  it("answers duplicates once, reports unknowns and invalid values without failing", async () => {
    const body = await results({
      observables: [
        { type: "domain", value: "Unknown.Example." },
        { type: "domain", value: "unknown.example" },
        { type: "ipv4", value: "1.0.4.9" },
        { type: "ipv4", value: "999.1.1.1" },
        { type: "domain", value: "private-b.example" },
        { type: "asn", value: "as38803" },
      ],
    });
    expect(body.results.map((r) => [r.type, r.value, r.found])).toEqual([
      ["domain", "unknown.example", false],
      ["ipv4", "1.0.4.9", false],
      ["ipv4", "999.1.1.1", false],
      ["domain", "private-b.example", false],
      ["asn", "AS38803", false],
    ]);
    const [unknown, routed, invalid, privateB, asn] = body.results;
    expect(unknown).toMatchObject({
      input: "Unknown.Example.",
      entity_id: null,
      ttl_seconds: 3600,
      reputation: null,
      network: null,
      cve: null,
      relationships: [],
      sources: [],
    });
    // Network context is returned for routed space even when nothing else is known.
    expect(routed!.network).toEqual({
      asn: 38803,
      as_org: "GTELECOM-AS-AP Gtelecom Pty Ltd",
      prefix: "1.0.4.0/23",
      country: "AU",
    });
    expect(routed!.ttl_seconds).toBe(86400);
    expect(invalid!.error?.code).toBe("INVALID_OBSERVABLE");
    expect(privateB!.entity_id).toBeNull();
    expect(asn!.network).toMatchObject({
      asn: 38803,
      prefix: null,
      country: "AU",
    });
  });

  it("merges NVD, EPSS, KEV and OSV into the CVE section", async () => {
    const request = {
      observables: [
        { type: "cve", value: "cve-2099-0001" },
        { type: "cve", value: "CVE-2099-0002" },
      ],
      include: ["cve"],
    };
    const first = await results(request);
    // OSV is fetched after the response and cached.
    expect(first.results[0]!.pending_sources).toEqual(["osv"]);
    expect(first.results[0]!.ttl_seconds).toBe(300);
    expect(await runLookupJobs()).toBe(1);
    clearDatasetCache();
    const body = await results(request);
    const [cve, other] = body.results;
    expect(cve).toMatchObject({
      value: "CVE-2099-0001",
      found: true,
      pending_sources: [],
      cve: {
        id: "CVE-2099-0001",
        description:
          "Synthetic path traversal in Example Demo App before 1.0.1.",
        published: "2099-01-01T00:00:00.000Z",
        status: "Analyzed",
        cvss: { version: "3.1", base_score: 9.8 },
        cwe: ["CWE-22"],
        kev: {
          listed: true,
          date_added: "2099-01-02",
          due_date: "2099-01-23",
          ransomware: "Unknown",
        },
        epss: { score: 0.97, percentile: 0.999, date: "2099-01-03" },
        osv_ids: ["EXAMPLE-SA-2099:0001", "GHSA-xxxx-yyyy-zzzz"],
        affected: [
          { vendor: "example", product: "demo-app", versions: "< 1.0.1" },
        ],
        references: [
          {
            url: "https://example.test/advisories/demo-app",
            tags: ["Vendor Advisory"],
          },
        ],
      },
      reputation: null,
      network: null,
      relationships: [],
    });
    expect(cve!.sources.map((s) => s.source_id)).toEqual([
      "cisa-kev",
      "epss",
      "nvd",
      "osv",
    ]);
    expect(cve!.ttl_seconds).toBe(21600);
    expect(other!.cve).toMatchObject({
      kev: { listed: false },
      osv_ids: [],
      epss: { score: 0.001 },
    });
  });

  it("applies the tenant's source policy to every section", async () => {
    await db.batch(
      ["threatfox", "iptoasn", "nvd"].map((source) =>
        db
          .prepare(
            "INSERT INTO tenant_source_policy VALUES('tenant-a',?,0,'Not licensed for this workspace',?)",
          )
          .bind(source, now.toISOString()),
      ),
    );
    try {
      const body = await results({
        observables: [
          { type: "ipv4", value: "203.0.113.7" },
          { type: "cve", value: "CVE-2099-0001" },
        ],
      });
      const [ip, cve] = body.results;
      expect(ip!.reputation).toBeNull();
      expect(ip!.network).toBeNull();
      expect(ip!.sources.map((s) => s.source_id)).toEqual(["mitre"]);
      expect(cve!.cve?.cvss).toBeNull();
      expect(cve!.sources.map((s) => s.source_id)).not.toContain("nvd");
      const otherTenant = await results(
        { observables: [{ type: "ipv4", value: "203.0.113.7" }] },
        { key: keys.other },
      );
      expect(otherTenant.results[0]!.reputation?.classification).toBe(
        "malicious",
      );
    } finally {
      await db
        .prepare("DELETE FROM tenant_source_policy WHERE tenant_id='tenant-a'")
        .run();
    }
  });

  it("refreshes GreyNoise and CrowdSec into a private cache within budget", async () => {
    const keyed = {
      GREYNOISE_API_KEY: "test-greynoise",
      CROWDSEC_API_KEY: "test-crowdsec",
      GREYNOISE_DAILY_LIMIT: "2",
    };
    const request = {
      observables: [
        { type: "ipv4", value: "198.51.100.7" },
        { type: "ipv4", value: "1.0.0.1" },
        { type: "ipv4", value: "203.0.113.9" },
      ],
      include: ["reputation"],
    };
    const first = await results(request, { env: keyed });
    expect(first.results.map((r) => r.pending_sources)).toEqual([
      ["crowdsec", "greynoise"],
      ["crowdsec", "greynoise"],
      ["crowdsec"],
    ]);
    // One job per source, run by the enrich queue.
    expect(await runLookupJobs(keyed)).toBe(2);
    const second = await results(request, { env: keyed });
    const [scanner, riot, unseen] = second.results;
    expect(scanner).toMatchObject({
      found: true,
      entity_id: null,
      ttl_seconds: 86400,
      pending_sources: [],
      reputation: {
        classification: "malicious",
        scanner: {
          is_scanner: true,
          benign_service: false,
          name: "Example Scanner",
          source_id: "greynoise",
        },
        tags: ["community-blocklist", "ssh:bruteforce", "tcp:scan"],
      },
    });
    expect(
      scanner!.sources.map((s) => [s.source_id, s.commercial_use]),
    ).toEqual([
      ["crowdsec", false],
      ["greynoise", false],
    ]);
    expect(riot!.reputation).toMatchObject({
      classification: "benign",
      scanner: { benign_service: true, name: "Cloudflare" },
    });
    // The GreyNoise daily budget (2) was spent; no further GreyNoise call.
    expect(unseen!.found).toBe(false);
    expect(unseen!.pending_sources).toEqual([]);
    expect(
      fake.calls.filter((c) => c.startsWith("https://api.greynoise.io/")),
    ).toHaveLength(2);
    // Cached answers never enter the shared graph.
    const search = await app.request(
      "/v1/search?q=198.51.100.7",
      { headers: { Authorization: "Bearer " + keys.other } },
      env(),
      ctx,
    );
    expect(((await search.json()) as { data: unknown[] }).data).toEqual([]);
    // Without the key the source is disabled, even with a warm cache.
    const unkeyed = await results(request);
    expect(unkeyed.results[0]!.found).toBe(false);
    // Tenant B has its own partition: A's answers, timing and pending
    // state are invisible, and the spent GreyNoise budget is shared.
    const otherTenant = await results(request, { key: keys.other, env: keyed });
    expect(otherTenant.results[0]).toMatchObject({
      found: false,
      reputation: null,
      sources: [],
      pending_sources: ["crowdsec"],
    });
  });

  it("stays within a fixed D1 statement budget when a source's daily budget is spent", async () => {
    const keyed = {
      GREYNOISE_API_KEY: "test-greynoise",
      CROWDSEC_API_KEY: "test-crowdsec",
      GREYNOISE_DAILY_LIMIT: "2",
      CROWDSEC_DAILY_LIMIT: "60",
    };
    const crowdsecSpent =
      (await db
        .prepare(
          "SELECT count FROM rate_limits WHERE bucket LIKE 'budget:crowdsec:%'",
        )
        .first<number>("count")) ?? 0;
    const observables = Array.from({ length: 500 }, (_, i) => ({
      type: "ipv4",
      value: "100.64." + Math.floor(i / 250) + "." + (i % 250),
    }));
    const { proxy, count } = countingDb();
    const response = await lookup(
      { observables, include: ["reputation"] },
      { env: { ...keyed, DB: proxy } },
    );
    expect(response.status).toBe(200);
    const body = LookupResponseSchema.parse(await response.json());
    expect(body.results).toHaveLength(500);
    // Independent of the number of observables.
    expect(count()).toBeLessThan(40);
    const pending = body.results.map((r) => r.pending_sources.join(","));
    expect(pending.filter((p) => p.includes("greynoise"))).toHaveLength(0);
    // Ten claimed now; the rest of today's CrowdSec budget waits for later lookups.
    expect(pending.filter((p) => p === "crowdsec")).toHaveLength(
      60 - crowdsecSpent,
    );
    expect(
      await db
        .prepare(
          "SELECT COUNT(*) AS n FROM source_lookup_cache WHERE source_id='crowdsec' AND lookup_key IN (SELECT value FROM json_each(?)) AND status='pending'",
        )
        .bind(
          JSON.stringify(
            await Promise.all(
              observables
                .slice(0, 20)
                .map(async (o) => (await normalise(o.value, "ipv4")).id),
            ),
          ),
        )
        .first("n"),
    ).toBe(10);
  });

  it("retries failed refreshes and refunds the budget on the final attempt", async () => {
    await runLookupJobs({ CROWDSEC_API_KEY: "test-crowdsec" });
    const key = (await normalise("100.64.9.9", "ipv4")).id;
    const budget = "budget:crowdsec:" + new Date().toISOString().slice(0, 10);
    const spent = async () =>
      (await db
        .prepare("SELECT count FROM rate_limits WHERE bucket=?")
        .bind(budget)
        .first<number>("count")) ?? 0;
    await db
      .prepare(
        "INSERT INTO source_lookup_cache(source_id,scope,lookup_key,status,data,fetched_at,expires_at) VALUES('crowdsec','tenant-a',?,'pending','{}',?,?)",
      )
      .bind(
        key,
        new Date().toISOString(),
        new Date(Date.now() + 1800000).toISOString(),
      )
      .run();
    const before = await spent();
    const failing: typeof fetch = async () =>
      new Response("busy", { status: 503 });
    const payload = {
      mode: "source-lookup" as const,
      source: "crowdsec" as const,
      scope: "tenant-a",
      budget,
      items: [{ key, value: "100.64.9.9" }],
    };
    const lookupEnv = {
      DB: db,
      ARCHIVE: bucket,
      CROWDSEC_API_KEY: "test-crowdsec",
    };
    await expect(
      processLookupJob(lookupEnv, payload, 1, failing),
    ).rejects.toThrow(/retrying/);
    expect(
      await db
        .prepare(
          "SELECT status FROM source_lookup_cache WHERE source_id='crowdsec' AND lookup_key=?",
        )
        .bind(key)
        .first("status"),
    ).toBe("pending");
    expect(await spent()).toBe(before);
    expect(
      await processLookupJob(lookupEnv, payload, FINAL_ATTEMPT, failing),
    ).toEqual({ done: 0, refunded: 1 });
    expect(
      await db
        .prepare(
          "SELECT status FROM source_lookup_cache WHERE source_id='crowdsec' AND lookup_key=?",
        )
        .bind(key)
        .first("status"),
    ).toBe("error");
    expect(await spent()).toBe(before - 1);
    // A finished row is skipped by a late redelivery.
    expect(await processLookupJob(lookupEnv, payload, 1, failing)).toEqual({
      done: 0,
      refunded: 0,
    });
  });

  it("is deterministic for the same stored data", async () => {
    const request = {
      observables: [
        { type: "ipv4", value: "203.0.113.7" },
        { type: "cve", value: "CVE-2099-0001" },
        { type: "ipv6", value: "2001:DB8::1" },
      ],
    };
    const a = await results(request);
    const b = await results(request);
    expect(a.results).toEqual(b.results);
    expect(a.results[2]).toMatchObject({
      value: "2001:db8::1",
      network: { asn: 64501, prefix: "2001:db8::/32" },
    });
  });

  it("uses its own rate-limit bucket and sends Retry-After", async () => {
    const limited = { LOOKUP_RATE_LIMIT: "1" };
    await db.prepare("DELETE FROM rate_limits").run();
    const request = {
      observables: [{ type: "domain", value: "rate.example" }],
    };
    expect((await lookup(request, { env: limited })).status).toBe(200);
    const blocked = await lookup(request, { env: limited });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("Retry-After"))).toBeGreaterThan(0);
    expect(await errorCode(blocked)).toBe("RATE_LIMITED");
    const me = await app.request(
      "/v1/me",
      { headers: { Authorization: "Bearer " + keys.reader } },
      env(limited),
      ctx,
    );
    expect(me.status).toBe(200);
  });

  it("refuses bulk sync for datasets and lookup-only sources", async () => {
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES('key-feeds','tenant-a','user-a','Feeds',?,?,?)",
      )
      .bind(
        await digest("test-feeds-writer"),
        JSON.stringify(["feeds:write", "feeds:read"]),
        now.toISOString(),
      )
      .run();
    for (const id of ["iptoasn", "greynoise"]) {
      const response = await app.request(
        "/v1/feeds/" + id + "/sync",
        {
          method: "POST",
          headers: { Authorization: "Bearer test-feeds-writer" },
        },
        env(),
        ctx,
      );
      expect(response.status).toBe(409);
      expect(await errorCode(response)).toBe("FEED_NOT_SYNCABLE");
    }
    const feeds = await app.request(
      "/v1/feeds",
      { headers: { Authorization: "Bearer test-feeds-writer" } },
      env(),
      ctx,
    );
    const data = ((await feeds.json()) as { data: unknown }).data as {
      id: string;
      enabled: number;
      commercial_use: number | null;
    }[];
    expect(data.find((f) => f.id === "iptoasn")).toMatchObject({
      enabled: 1,
      commercial_use: 1,
    });
    expect(data.find((f) => f.id === "greynoise")).toMatchObject({
      enabled: 0,
    });
    expect(await entityId("vulnerability", "CVE-2099-0001")).toMatch(
      /^vulnerability_/,
    );
  });
});
