import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Miniflare } from "miniflare";
import { z } from "zod";
import { migratedDatabase } from "./hub-fixtures";
import { app } from "../apps/api/src/index";
import { Repository } from "../packages/database/src/repository";
import { digest } from "../packages/intel/src/normalise";
import { LookupSourceSchema } from "../packages/schemas/src/lookup";
import type { SourceProvenance } from "../packages/schemas/src/index";

let mf: Miniflare;
let db: D1Database;
const at = "2099-01-04T00:00:00.000Z";
const keys = { a: "test-entity-reader-a", b: "test-entity-reader-b" };
const ctx = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
} as unknown as ExecutionContext;
const Licences = z.array(LookupSourceSchema);
async function get(path: string, key = keys.a) {
  const response = await app.request(
    path,
    { headers: { Authorization: "Bearer " + key } },
    { DB: db, WEB_ORIGIN: "https://web.test" },
    ctx,
  );
  expect(response.status).toBe(200);
  return (await response.json()) as Record<string, unknown> & {
    source_licences?: unknown;
  };
}
const byId = (licences: unknown) =>
  new Map(Licences.parse(licences).map((s) => [s.source_id, s]));
const provenance = (
  sourceId: string,
  extra: Partial<SourceProvenance> = {},
): SourceProvenance => ({
  sourceId,
  sourceName: sourceId,
  retrievedAt: at,
  redistributable: true,
  ...extra,
});

beforeAll(async () => {
  ({ mf, db } = await migratedDatabase());
  // Every source here is stored data; any network call is a bug.
  vi.stubGlobal("fetch", () => {
    throw new Error("Entity APIs must not make network requests");
  });
  await db.batch([
    db
      .prepare(
        "INSERT INTO tenants(id,name,created_at) VALUES('tenant-a','A',?),('tenant-b','B',?)",
      )
      .bind(at, at),
    db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES('key-a','tenant-a','user-a','Foiled',?,?,?),('key-b','tenant-b','user-b','B',?,?,?)",
      )
      .bind(
        await digest(keys.a),
        JSON.stringify(["intel:read"]),
        at,
        await digest(keys.b),
        JSON.stringify(["intel:read"]),
        at,
      ),
  ]);
  const repo = new Repository(db);
  const actor = {
    id: "intrusion-set--licence",
    type: "threat-actor" as const,
    name: "Licence Group",
    description: "Synthetic",
    aliases: [],
    externalId: "G9998",
    data: {},
  };
  // Two MITRE records (older and newer) and a MISP galaxy record that was
  // delivered as non-redistributable.
  await repo.putEntity({
    ...actor,
    provenance: provenance("mitre", {
      sourceRecordId: "old",
      publishedAt: "2098-01-01T00:00:00.000Z",
      retrievedAt: "2099-01-01T00:00:00.000Z",
      sourceUrl: "https://attack.example.test/old",
    }),
  });
  await repo.putEntity({
    ...actor,
    provenance: provenance("misp", {
      sourceRecordId: "misp-1",
      redistributable: false,
      sourceUrl: "https://misp.example.test/galaxy",
    }),
  });
  await repo.putEntity({
    ...actor,
    provenance: provenance("mitre", {
      sourceRecordId: "new",
      publishedAt: "2098-06-01T00:00:00.000Z",
      sourceUrl: "https://attack.example.test/G9998",
    }),
  });
  await repo.putEntity({
    id: "campaign--licence",
    type: "campaign",
    name: "Licence Campaign",
    description: "",
    aliases: [],
    data: {},
    provenance: provenance("otx"),
  });
  await repo.putEntity({
    id: "attack-pattern--licence",
    type: "attack-technique",
    name: "Licence Technique",
    description: "",
    aliases: [],
    externalId: "T9998",
    data: {},
    provenance: provenance("mitre"),
  });
  // An older MITRE technique record with a URL; the newest record has none.
  await repo.putEntity({
    id: "attack-pattern--licence",
    type: "attack-technique",
    name: "Licence Technique",
    description: "",
    aliases: [],
    externalId: "T9998",
    data: {},
    provenance: provenance("mitre", {
      sourceRecordId: "t-old",
      retrievedAt: "2099-01-01T00:00:00.000Z",
      sourceUrl: "https://attack.example.test/t-old",
    }),
  });
  // A MITRE relationship retrieved between the two: its URL is the newest.
  await repo.putRelationship({
    id: "rel-licence-mitre",
    sourceEntityId: "campaign--licence",
    targetEntityId: "attack-pattern--licence",
    relationshipType: "USES",
    assertionType: "source_claimed",
    confidence: 0.5,
    sourceIds: ["mitre"],
    provenance: provenance("mitre", {
      retrievedAt: "2099-01-02T00:00:00.000Z",
      sourceUrl: "https://attack.example.test/rel",
    }),
    createdAt: at,
    updatedAt: at,
  });
  // A ThreatFox relationship to the actor: its source counts on detail views.
  await repo.putRelationship({
    id: "rel-licence-uses",
    sourceEntityId: "intrusion-set--licence",
    targetEntityId: "attack-pattern--licence",
    relationshipType: "USES",
    assertionType: "source_claimed",
    confidence: 0.6,
    sourceIds: ["threatfox"],
    provenance: provenance("threatfox", {
      redistributable: false,
      sourceUrl: "https://threatfox.example.test/1",
    }),
    firstSeen: "2099-01-02T00:00:00.000Z",
    lastSeen: "2099-01-03T00:00:00.000Z",
    createdAt: at,
    updatedAt: at,
  });
}, 120000);
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
});

describe("per-source licences on entity APIs", () => {
  it("lists catalogue entities with lookup-shaped source_licences", async () => {
    const body = await get("/v1/actors?limit=100");
    const data = body.data as Array<Record<string, unknown>>;
    const item = data.find((e) => e.id === "intrusion-set--licence")!;
    // Existing entity fields stay as they were.
    expect(item).toMatchObject({ name: "Licence Group", externalId: "G9998" });
    const sources = byId(item.source_licences);
    expect([...sources.keys()]).toEqual(["misp", "mitre"]);
    expect(sources.get("mitre")).toEqual({
      source_id: "mitre",
      name: "MITRE ATT&CK",
      license: expect.any(String),
      redistributable: true,
      commercial_use: true,
      reliability: expect.any(Number),
      first_seen: "2098-01-01T00:00:00.000Z",
      last_seen: "2098-06-01T00:00:00.000Z",
      retrieved_at: at,
      source_url: "https://attack.example.test/G9998",
    });
    // MISP allows redistribution by licence row only when the record does.
    expect(sources.get("misp")).toMatchObject({
      redistributable: false,
      commercial_use: true,
      first_seen: null,
      source_url: "https://misp.example.test/galaxy",
    });

    const campaigns = (await get("/v1/campaigns")).data as Array<
      Record<string, unknown>
    >;
    const campaign = byId(
      campaigns.find((e) => e.id === "campaign--licence")!.source_licences,
    );
    // OTX has no recorded commercial-use terms; every feed is redistributable.
    expect(campaign.get("otx")).toMatchObject({
      redistributable: true,
      commercial_use: null,
    });
    const techniques = (await get("/v1/attack/techniques")).data as Array<
      Record<string, unknown>
    >;
    expect([
      ...byId(
        techniques.find((e) => e.id === "attack-pattern--licence")!
          .source_licences,
      ).keys(),
    ]).toEqual(["mitre"]);
  });

  it("adds relationship sources on detail views", async () => {
    const actor = await get("/v1/actors/intrusion-set--licence");
    expect(actor.entity).toMatchObject({ id: "intrusion-set--licence" });
    expect(actor.relationships).toHaveLength(1);
    const sources = byId(actor.source_licences);
    expect([...sources.keys()]).toEqual(["misp", "mitre", "threatfox"]);
    expect(sources.get("threatfox")).toMatchObject({
      redistributable: false,
      commercial_use: false,
      first_seen: "2099-01-02T00:00:00.000Z",
      last_seen: "2099-01-03T00:00:00.000Z",
      source_url: "https://threatfox.example.test/1",
    });

    const entity = await get("/v1/entities/intrusion-set--licence");
    expect(byId(entity.source_licences)).toEqual(sources);
    // The existing provenance list keeps its shape and name.
    const provenances = entity.sources as SourceProvenance[];
    expect(provenances.map((p) => p.sourceId).sort()).toEqual([
      "misp",
      "mitre",
      "mitre",
    ]);
    expect(entity.source_assertions).toEqual(entity.sources);
  });

  it("takes source_url from the newest record that has one", async () => {
    const technique = await get(
      "/v1/attack/techniques/attack-pattern--licence",
    );
    expect(byId(technique.source_licences).get("mitre")).toMatchObject({
      retrieved_at: at,
      source_url: "https://attack.example.test/rel",
    });
  });

  it("applies the tenant source policy", async () => {
    await db
      .prepare(
        "INSERT INTO tenant_source_policy VALUES('tenant-a','misp',0,'Not licensed',?),('tenant-a','threatfox',0,'Not licensed',?)",
      )
      .bind(at, at)
      .run();
    try {
      const list = (await get("/v1/actors?limit=100")).data as Array<
        Record<string, unknown>
      >;
      expect([
        ...byId(
          list.find((e) => e.id === "intrusion-set--licence")!.source_licences,
        ).keys(),
      ]).toEqual(["mitre"]);
      const detail = await get("/v1/entities/intrusion-set--licence");
      expect([...byId(detail.source_licences).keys()]).toEqual(["mitre"]);
      const actor = await get("/v1/actors/intrusion-set--licence");
      expect([...byId(actor.source_licences).keys()]).toEqual(["mitre"]);
      // Another tenant's policy is its own.
      const other = await get("/v1/actors/intrusion-set--licence", keys.b);
      expect([...byId(other.source_licences).keys()]).toEqual([
        "misp",
        "mitre",
        "threatfox",
      ]);
    } finally {
      await db
        .prepare("DELETE FROM tenant_source_policy WHERE tenant_id='tenant-a'")
        .run();
    }
  });
});
