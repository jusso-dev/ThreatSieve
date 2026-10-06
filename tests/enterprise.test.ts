import { beforeAll, afterAll, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { OperationsRepository } from "../packages/enterprise/src/repository";
import { normalise } from "../packages/intel/src/normalise";
import { WorkInput, MatchCriteria } from "../packages/schemas/src/enterprise";
import {
  EnvironmentSchema,
  type Principal,
  type Evidence,
} from "../packages/schemas/src/index";
import { scoreDossier } from "../packages/enterprise/src/scoring";
import {
  criterionMatches,
  requirementCoverage,
} from "../packages/enterprise/src/intelligence";
let mf: Miniflare,
  db: D1Database,
  a: OperationsRepository,
  b: OperationsRepository;
const principal: Principal = {
  tenantId: "enterprise-a",
  userId: "alice",
  keyId: "a",
  kind: "key",
  scopes: ["admin"],
};
const p = {
  sourceId: "mitre",
  sourceName: "Synthetic source",
  retrievedAt: new Date().toISOString(),
  redistributable: true,
};
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  for (const f of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + f, "utf8"),
    ))
      await db.prepare(sql).run();
  for (const [t, u] of [
    ["enterprise-a", "alice"],
    ["enterprise-b", "bob"],
  ]) {
    await db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind(t, t, p.retrievedAt)
      .run();
    await db
      .prepare("INSERT INTO users(id,email,created_at) VALUES(?,?,?)")
      .bind(u, u + "@example.test", p.retrievedAt)
      .run();
    await db
      .prepare(
        "INSERT INTO tenant_members(tenant_id,user_id,role) VALUES(?,?,?)",
      )
      .bind(t, u, "admin")
      .run();
  }
  a = new OperationsRepository(db, principal);
  b = new OperationsRepository(db, {
    ...principal,
    tenantId: "enterprise-b",
    userId: "bob",
  });
});
afterAll(async () => {
  await mf?.dispose();
});
it("normalizes CIDR host bits before deterministic identity generation", async () => {
  expect((await normalise("192.0.2.42/24")).id).toBe(
    (await normalise("192.0.2.0/24")).id,
  );
  expect((await normalise("2001:db8::1234/32")).normalizedValue).toBe(
    "2001:db8::/32",
  );
});
it("creates each operational object with audited history and tenant isolation", async () => {
  for (const kind of [
    "requirement",
    "investigation",
    "watchlist",
    "collection",
    "report",
    "playbook",
  ] as const) {
    const o = await a.save({
      kind,
      title: "Synthetic " + kind,
      question: "What evidence do we have?",
      trigger: "sighting.created",
      actions: [{ type: "notify" }],
    });
    expect((await a.get(o.id)).ownerId).toBe("alice");
    expect((await a.history(o.id)).data).toHaveLength(1);
    await expect(b.get(o.id)).rejects.toMatchObject({ status: 404 });
    expect((await b.list(kind)).data).toHaveLength(0);
  }
});
it("rejects foreign owners and references without leaking evidence", async () => {
  const privateObs = await normalise("private.enterprise.test");
  await b.intel.putObservable(
    privateObs,
    { ...p, sourceId: "customer" },
    b.tenant,
  );
  await expect(
    a.save({ kind: "investigation", title: "Invalid owner", ownerId: "bob" }),
  ).rejects.toMatchObject({ status: 400 });
  await expect(
    a.save({
      kind: "investigation",
      title: "Invalid reference",
      references: [{ type: "entity", id: privateObs.id }],
    }),
  ).rejects.toMatchObject({ status: 404 });
});
it("atomically rejects competing edits without partial history or references", async () => {
  const o = await a.save({ kind: "investigation", title: "Concurrent case" });
  const edits = await Promise.allSettled([
    a.save({ ...o, title: "First analyst" }, o.id, 1, "First edit"),
    a.save({ ...o, title: "Second analyst" }, o.id, 1, "Second edit"),
  ]);
  expect(edits.filter((x) => x.status === "fulfilled")).toHaveLength(1);
  expect((await a.get(o.id)).revision).toBe(2);
  expect((await a.history(o.id)).data).toHaveLength(2);
});
it("keeps sightings private and idempotent without asserting maliciousness", async () => {
  const input = {
    observable: { observable: "sighting.enterprise.test" },
    observedAt: p.retrievedAt,
    source: "dns",
    externalId: "sensor-event-1",
    count: 3,
    context: "Resolved by a customer endpoint",
  };
  const s = await a.recordSighting(input);
  expect((await a.recordSighting(input)).id).toBe(s.id);
  expect((await a.sightings(s.observableId)).data).toHaveLength(1);
  expect((await b.sightings(s.observableId)).data).toHaveLength(0);
  await expect(b.evidence(s.id)).rejects.toMatchObject({ status: 404 });
  await expect(a.recordSighting({ ...input, count: 5 })).rejects.toMatchObject({
    status: 409,
  });
  expect((await a.evidence(s.id)).data.malicious).toBeUndefined();
  expect((await a.evidence(s.id)).behavioural).toBe(false);
});
it("preserves timestamped analyst decisions and rejects foreign note citations", async () => {
  const o = await a.save({ kind: "investigation", title: "Decision log case" });
  await a.note(o.id, {
    type: "decision",
    body: "Reject attribution: no behavioural evidence.",
  });
  expect(
    (await a.history(o.id)).data.some((e) => e.event_type === "decision"),
  ).toBe(true);
  await expect(
    a.note(o.id, {
      body: "Unavailable evidence",
      references: [{ type: "evidence", id: "no-such-evidence" }],
    }),
  ).rejects.toMatchObject({ status: 404 });
});
it("does not score sightings or lack of intelligence as malicious", () => {
  const e = {
    id: "x",
    type: "observable" as const,
    name: "demo.test",
    description: "",
    aliases: [],
    data: {},
    provenance: p,
  };
  const ev: Evidence = {
    id: "ev",
    type: "telemetry",
    sourceId: "customer",
    provenance: { ...p, redistributable: false },
    data: { sighting: true },
    confidence: 0.9,
    createdAt: p.retrievedAt,
    behavioural: false,
  };
  const result = scoreDossier(e, [ev], [], EnvironmentSchema.parse({}));
  expect(result.threat.value).toBeNull();
  expect(result.relevance.value).toBe(40);
  expect(result.gaps.map((g) => g.code)).toContain("BEHAVIOUR_MISSING");
});
it("does not count stale or contradictory support as requirement coverage", async () => {
  const o = await a.save({
    kind: "requirement",
    title: "Unsupported PIR",
    question: "Is this supported?",
    criteria: { keywords: ["ransomware"] },
  });
  const result = await requirementCoverage(a, o);
  expect(result.coverage).toBe(0);
  expect(result.confidence).toBeNull();
  const e = {
    id: "x",
    type: "observable" as const,
    name: "demo.test",
    description: "",
    aliases: [],
    data: {},
    provenance: p,
  };
  const ev: Evidence = {
    id: "old",
    type: "feed",
    sourceId: "mitre",
    provenance: p,
    data: { description: "ransomware" },
    confidence: 1,
    observedAt: "2000-01-01T00:00:00.000Z",
    createdAt: p.retrievedAt,
    behavioural: false,
  };
  expect(
    criterionMatches(
      MatchCriteria.parse({
        keywords: ["ransomware"],
        from: "2026-01-01T00:00:00.000Z",
      }),
      e,
      [ev],
    ).matches,
  ).toBe(false);
});
it("validates bounded actions and disallows arbitrary commands in playbooks", () => {
  expect(() =>
    WorkInput.parse({
      kind: "playbook",
      title: "Unsafe action",
      trigger: "sighting.created",
      actions: [{ type: "shell", target: "curl attacker.test" }],
    }),
  ).toThrow();
});

it("matches exact structured context, never country substrings", () => {
  const entity = {
    id: "x",
    type: "malware" as const,
    name: "Demo",
    aliases: [],
    description: "",
    data: {},
    provenance: p,
  };
  const evidence: Evidence = {
    id: "e",
    type: "feed",
    sourceId: "mitre",
    provenance: p,
    data: { country: "Austria" },
    confidence: 0.9,
    createdAt: p.retrievedAt,
    behavioural: false,
  };
  expect(
    criterionMatches(MatchCriteria.parse({ countries: ["AU"] }), entity, [
      evidence,
    ]).matches,
  ).toBe(false);
  expect(
    criterionMatches(MatchCriteria.parse({ countries: ["Austria"] }), entity, [
      evidence,
    ]).matches,
  ).toBe(true);
});
it("dispatches tenant-private sightings to deterministic watchlists and idempotent playbooks", async () => {
  const { scheduleOperations, processOperation } =
    await import("../packages/enterprise/src/automation");
  const watch = await a.save({
    kind: "watchlist",
    title: "Demo observed domain watch",
    criteria: { keywords: ["automation.enterprise.test"] },
    triggers: ["sighting.created"],
  });
  const playbook = await a.save({
    kind: "playbook",
    title: "Demo sighting triage",
    status: "active",
    trigger: "sighting.created",
    criteria: { keywords: ["automation.enterprise.test"] },
    actions: [
      { type: "notify" },
      { type: "tag", target: "observed" },
      { type: "create-investigation", target: "Demo automated case" },
      { type: "add-to-watchlist", target: watch.id },
    ],
  });
  await b.save({
    kind: "watchlist",
    title: "Foreign private watch",
    criteria: { keywords: ["automation.enterprise.test"] },
  });
  const sighting = await a.recordSighting({
    observable: { observable: "automation.enterprise.test" },
    observedAt: p.retrievedAt,
    source: "edr",
    externalId: "automation-1",
  });
  await scheduleOperations(db);
  const drain = async () => {
    for (let i = 0; i < 20; i++) {
      const jobs = await db
        .prepare(
          "SELECT data FROM pipeline_jobs WHERE stage='operations' AND status='queued' LIMIT 100",
        )
        .all<{ data: string }>();
      if (!jobs.results.length) break;
      for (const r of jobs.results)
        await processOperation(db, JSON.parse(r.data));
      await scheduleOperations(db);
    }
  };
  await drain();
  const matches = await db
    .prepare(
      "SELECT * FROM workspace_matches WHERE tenant_id=? AND object_id=?",
    )
    .bind(a.tenant, watch.id)
    .all();
  expect(matches.results).toHaveLength(1);
  expect(
    (
      await db
        .prepare("SELECT * FROM workspace_matches WHERE tenant_id=?")
        .bind(b.tenant)
        .all()
    ).results,
  ).toHaveLength(0);
  const executed = await db
    .prepare(
      "SELECT * FROM automation_executions WHERE tenant_id=? AND playbook_id=?",
    )
    .bind(a.tenant, playbook.id)
    .all();
  expect(executed.results).toHaveLength(1);
  await a.save(
    { ...watch, title: "Demo edited watchlist" },
    watch.id,
    watch.revision,
    "Test unrelated edit",
  );
  expect(
    await db
      .prepare(
        "SELECT 1 FROM workspace_links WHERE tenant_id=? AND object_id=? AND target_id=? AND relation='automation_member'",
      )
      .bind(a.tenant, watch.id, sighting.observableId)
      .first(),
  ).not.toBeNull();

  await expect(
    b.removeAutomaticMember(watch.id, sighting.observableId),
  ).rejects.toThrow();
  const replay = await db
    .prepare(
      "SELECT data FROM pipeline_jobs WHERE stage='operations' AND json_extract(data,'$.payload.objectId')=? LIMIT 1",
    )
    .bind(playbook.id)
    .first<{ data: string }>();
  await processOperation(db, JSON.parse(replay!.data));
  expect(
    (await a.list("investigation", "Demo automated case")).data,
  ).toHaveLength(1);
  expect(
    (
      await db
        .prepare("SELECT * FROM entity_tags WHERE tenant_id=? AND entity_id=?")
        .bind(a.tenant, sighting.observableId)
        .all()
    ).results,
  ).toHaveLength(1);
  await a.removeAutomaticMember(watch.id, sighting.observableId);
  expect(
    await db
      .prepare(
        "SELECT 1 FROM workspace_links WHERE tenant_id=? AND object_id=? AND target_id=? AND relation='automation_member'",
      )
      .bind(a.tenant, watch.id, sighting.observableId)
      .first(),
  ).toBeNull();
});

it("applies tenant source exclusions and ratings without changing another tenant", async () => {
  const { sourceReliabilities } =
    await import("../packages/enterprise/src/sources");
  const observable = await normalise("source-policy.enterprise.test");
  await a.intel.putObservable(observable, p);
  const evidence: Evidence = {
    id: "source-policy-evidence",
    observableId: observable.id,
    type: "feed",
    sourceId: "mitre",
    provenance: p,
    data: { malicious: true },
    confidence: 0.9,
    createdAt: p.retrievedAt,
    behavioural: false,
  };
  await a.intel.putEvidence(observable.id, evidence);
  await db
    .prepare("INSERT INTO tenant_source_policy VALUES(?,?,?,?,?)")
    .bind(a.tenant, "mitre", 0, "Synthetic exclusion for test", p.retrievedAt)
    .run();
  expect(await a.intel.evidence(observable.id, 100, a.tenant)).toHaveLength(0);
  expect(await b.intel.evidence(observable.id, 100, b.tenant)).toHaveLength(1);
  await db
    .prepare("INSERT INTO source_ratings VALUES(?,?,?,?,?,?,?)")
    .bind(
      a.tenant,
      "mitre",
      "D",
      4,
      "Synthetic rating for test",
      "alice",
      p.retrievedAt,
    )
    .run();
  expect(
    (await sourceReliabilities(db, a.tenant)).find((s) => s.id === "mitre")!
      .reliability,
  ).toBe(0.4);
  expect(
    (await sourceReliabilities(db, b.tenant)).find((s) => s.id === "mitre")!
      .reliability,
  ).toBe(0.95);
  await db
    .prepare("DELETE FROM tenant_source_policy WHERE tenant_id=?")
    .bind(a.tenant)
    .run();
});
it("retains contradictory relationship assertions instead of overwriting their provenance", async () => {
  const source = await normalise("assertion-one.enterprise.test"),
    target = await normalise("assertion-two.enterprise.test");
  await a.intel.putObservable(source, p);
  await a.intel.putObservable(target, p);
  const base = {
    id: "assertion-history",
    sourceEntityId: source.id,
    targetEntityId: target.id,
    relationshipType: "RESOLVES_TO",
    assertionType: "source_claimed" as const,
    confidence: 0.9,
    sourceIds: ["mitre"],
    provenance: p,
    createdAt: p.retrievedAt,
    updatedAt: p.retrievedAt,
  };
  await a.intel.putRelationship(base);
  await a.intel.putRelationship({
    ...base,
    createdAt: "2026-10-06T10:00:00.000Z",
    updatedAt: "2026-10-06T10:00:00.000Z",
    provenance: { ...p, retrievedAt: "2026-10-06T10:00:00.000Z" },
  });
  expect(
    (
      await db
        .prepare(
          "SELECT id FROM relationship_assertions WHERE relationship_id=?",
        )
        .bind(base.id)
        .all()
    ).results,
  ).toHaveLength(1);

  await a.intel.putRelationship({
    ...base,
    confidence: 0.4,
    sourceIds: ["misp"],
    provenance: { ...p, sourceId: "misp" },
  });
  expect(
    (
      await db
        .prepare(
          "SELECT source_id FROM relationship_assertions WHERE relationship_id=?",
        )
        .bind(base.id)
        .all()
    ).results,
  ).toHaveLength(2);
});
it("finds shortest paths only within authorized graph edges", async () => {
  const { shortestPath, connectedNodes } =
    await import("../packages/enterprise/src/graph");
  const edge = (from: string, to: string) => ({
    id: from + to,
    sourceEntityId: from,
    targetEntityId: to,
    relationshipType: "USES",
    assertionType: "source_claimed" as const,
    confidence: 0.9,
    sourceIds: ["mitre"],
    provenance: p,
    createdAt: p.retrievedAt,
    updatedAt: p.retrievedAt,
  });
  const edges = [
    edge("a", "b"),
    edge("b", "c"),
    edge("a", "d"),
    edge("d", "e"),
  ];
  expect(shortestPath(edges, "a", "c")).toEqual(["a", "b", "c"]);
  expect(shortestPath(edges, "a", "foreign")).toBeNull();
  expect([...connectedNodes(edges, "a", ["b"])]).not.toContain("c");
});
it("publishes a stable TAXII snapshot and omits restricted source entities", async () => {
  const { publishCollection } =
    await import("../packages/enterprise/src/taxii");
  const allowed = await normalise("exportable.enterprise.test"),
    restricted = await normalise("restricted.enterprise.test");
  await a.intel.putObservable(allowed, p);
  await a.intel.putObservable(restricted, {
    ...p,
    sourceId: "misp",
    redistributable: false,
  });
  const c = await a.save({
    kind: "collection",
    title: "Demo distribution",
    status: "published",
    publication: "taxii",
    references: [
      { type: "entity", id: allowed.id },
      { type: "entity", id: restricted.id },
    ],
  });
  const first = await publishCollection(a, c);
  expect(first.objects).toBe(1);
  const row = await db
    .prepare(
      "SELECT data FROM taxii_objects WHERE tenant_id=? AND collection_id=? AND generation=?",
    )
    .bind(a.tenant, c.id, first.generation)
    .first<{ data: string }>();
  expect(JSON.parse(row!.data).value).toBe("exportable.enterprise.test");
  await expect(publishCollection(b, c)).rejects.toBeTruthy();
});
it("only accepts operator-approved HTTPS integration targets in the current tenant", async () => {
  const { integrationTargets } =
    await import("../packages/enterprise/src/integrations");
  const target = {
    id: "soc",
    name: "SOC receiver",
    url: "https://receiver.example.test/events",
    allowedHost: "receiver.example.test",
    tenantIds: [a.tenant],
    secretName: "SOC_TOKEN",
  };
  expect(integrationTargets(JSON.stringify([target]), a.tenant)).toHaveLength(
    1,
  );
  expect(integrationTargets(JSON.stringify([target]), b.tenant)).toHaveLength(
    0,
  );
  for (const url of [
    "http://receiver.example.test/events",
    "https://127.0.0.1/admin",
    "https://user:pass@receiver.example.test/",
    "https://unapproved.test/events",
  ]) {
    expect(() =>
      integrationTargets(JSON.stringify([{ ...target, url }]), a.tenant),
    ).toThrow();
  }
});
it("delivers integrations with stable idempotency headers and does not forward credentials on redirects", async () => {
  const { deliverIntegration } =
    await import("../packages/enterprise/src/integrations");
  const obs = await normalise("integration.enterprise.test");
  await a.intel.putObservable(obs, p);
  const env = {
    DB: db,
    INTEGRATION_TARGETS: JSON.stringify([
      {
        id: "soc",
        name: "SOC",
        url: "https://receiver.example.test/events",
        allowedHost: "receiver.example.test",
        tenantIds: [a.tenant],
        secretName: "SOC_TOKEN",
      },
    ]),
    INTEGRATION_SECRETS: JSON.stringify({
      SOC_TOKEN: "synthetic-integration-test-token",
    }),
  } as import("../apps/api/src/env").AppEnv;
  const job: import("../packages/schemas/src/index").PipelineJob = {
    jobId: "integration-test",
    entityId: obs.id,
    tenantId: a.tenant,
    stage: "operations",
    attempt: 0,
    createdAt: p.retrievedAt,
    correlationId: "test",
    payload: {
      mode: "integration",
      target: "soc",
      eventId: "event",
      eventType: "indicator.created",
      ownerId: "alice",
    },
  };
  await a.intel.enqueue(job);
  let delivered: RequestInit | undefined;
  await deliverIntegration(env, job, async (_url, init) => {
    delivered = init;
    return new Response(null, { status: 202 });
  });
  expect(new Headers(delivered!.headers).get("Idempotency-Key")).toBe(
    job.jobId,
  );
  expect(delivered!.redirect).toBe("manual");
  expect(String(delivered!.body)).not.toContain(
    "synthetic-integration-test-token",
  );
  await expect(
    deliverIntegration(
      env,
      job,
      async () =>
        new Response(null, {
          status: 302,
          headers: { Location: "https://unapproved.test" },
        }),
    ),
  ).rejects.toThrow("delivery rejected");
});
it("escapes spreadsheet formulas including whitespace-prefixed values", async () => {
  const { csvCell } = await import("../packages/enterprise/src/export");
  expect(csvCell('  =HYPERLINK("https://example.test")')).toContain("'  =");
  expect(csvCell("plain")).toBe('"plain"');
});
