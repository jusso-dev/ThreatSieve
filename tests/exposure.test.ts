import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { digest } from "../packages/intel/src/normalise";
import { app } from "../apps/api/src/index";
import { EnvironmentSchema } from "../packages/schemas/src/index";
import {
  cvePriorityTitle,
  evaluateCustomerExposure,
  exposureRelevanceLabel,
  hasGroundingInventory,
} from "../packages/enterprise/src/scoring";

let mf: Miniflare;
let db: D1Database;

beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  for (const name of readdirSync("migrations").sort()) {
    const sql = readFileSync("migrations/" + name, "utf8");
    for (const statement of migrationStatements(sql))
      await db.prepare(statement).run();
  }
  const now = new Date().toISOString();
  await db
    .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
    .bind("tenant-exposure", "Exposure", now)
    .run();
  await db
    .prepare(
      "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(
      "key-exposure",
      "tenant-exposure",
      "analyst-exposure",
      "Exposure test",
      await digest("exposure-test-key"),
      JSON.stringify(["admin", "intel:read"]),
      now,
    )
    .run();
});

afterAll(async () => {
  await mf?.dispose();
});

const emptyEnv = () => EnvironmentSchema.parse({});

describe("EnvironmentSchema.assets (leaf 1.3.2)", () => {
  it("accepts assets[] and defaults missing assets to []", () => {
    const parsed = EnvironmentSchema.parse({
      technologies: ["FortiGate"],
      products: ["FortiOS"],
    });
    expect(parsed.assets).toEqual([]);
    expect(parsed.technologies).toEqual(["FortiGate"]);
    expect(parsed.products).toEqual(["FortiOS"]);

    const withAssets = EnvironmentSchema.parse({
      assets: [
        {
          id: "fw-1",
          name: "Edge firewall",
          product: "FortiOS",
          version: "7.2.0",
          vendor: "Fortinet",
          criticality: "critical",
          internetExposed: true,
          owner: "netops",
          inventoryFreshness: "2026-09-01T00:00:00.000Z",
          lastSeenAt: "2026-09-01T00:00:00.000Z",
        },
      ],
    });
    expect(withAssets.assets).toHaveLength(1);
    expect(withAssets.assets[0]!.product).toBe("FortiOS");
    expect(withAssets.assets[0]!.criticality).toBe("critical");
  });

  it("PUT /v1/environment persists assets and GET returns them", async () => {
    const env = { DB: db, WEB_ORIGIN: "https://web.test" };
    const headers = {
      Authorization: "Bearer exposure-test-key",
      "Content-Type": "application/json",
    };
    const body = EnvironmentSchema.parse({
      technologies: ["Windows"],
      assets: [
        {
          id: "host-1",
          name: "Jump box",
          product: "OpenSSH",
          version: "9.0",
          criticality: "high",
          internetExposed: true,
          owner: "secops",
        },
      ],
    });
    const put = await app.request(
      "/v1/environment",
      { method: "PUT", headers, body: JSON.stringify(body) },
      env,
    );
    expect(put.status, await put.clone().text()).toBe(200);
    const putJson = (await put.json()) as { assets: { id: string }[] };
    expect(putJson.assets).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "host-1" })]),
    );

    const get = await app.request(
      "/v1/environment",
      { headers: { Authorization: "Bearer exposure-test-key" } },
      env,
    );
    expect(get.status).toBe(200);
    const got = EnvironmentSchema.parse(await get.json());
    expect(got.assets).toHaveLength(1);
    expect(got.assets[0]!.product).toBe("OpenSSH");
    expect(got.technologies).toContain("Windows");

    // Legacy row without assets still parses on GET after raw insert
    await db
      .prepare(
        "INSERT INTO customer_environments VALUES(?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at",
      )
      .bind(
        "tenant-exposure",
        JSON.stringify({ technologies: ["LegacyOnly"] }),
        new Date().toISOString(),
      )
      .run();
    const legacyGet = await app.request(
      "/v1/environment",
      { headers: { Authorization: "Bearer exposure-test-key" } },
      env,
    );
    const legacyParsed = EnvironmentSchema.parse(await legacyGet.json());
    expect(legacyParsed.assets).toEqual([]);
    expect(legacyParsed.technologies).toEqual(["LegacyOnly"]);
  });
});

describe("empty profile + KEV wording contract (leaf 1.3.2)", () => {
  it("does not claim customer exposure; relevance stays null", () => {
    const claim = evaluateCustomerExposure({
      environment: emptyEnv(),
      products: [{ product: "FortiOS", version: "7.2.0" }],
      kev: true,
    });
    expect(hasGroundingInventory(emptyEnv())).toBe(false);
    expect(claim.applicability).toBe("unknown");
    expect(claim.relevance).toBeNull();
    expect(claim.matchedAssetIds).toEqual([]);
    expect(claim.wording.join(" ")).toMatch(/Known exploited vulnerability/i);
    expect(claim.wording.join(" ")).toMatch(
      /Applicability to your environment unknown/i,
    );
    expect(claim.wording.join(" ").toLowerCase()).not.toContain(
      "your exposed asset",
    );
    expect(claim.wording.join(" ")).not.toMatch(
      /Exploited vulnerability exposure/i,
    );
    expect(cvePriorityTitle(claim)).toBe("Known exploited vulnerability");
    expect(cvePriorityTitle(claim)).not.toMatch(
      /Exploited vulnerability exposure/i,
    );
    expect(exposureRelevanceLabel(claim)).toBe("Unknown");
    expect(exposureRelevanceLabel(claim, 0)).toBe("Unknown");
  });
});

describe("asset-grounded exposure claims (leaf 1.3.2)", () => {
  const now = Date.parse("2026-10-13T00:00:00.000Z");

  it("matches exact product/version, shows asset ids and freshness", () => {
    const environment = EnvironmentSchema.parse({
      assets: [
        {
          id: "fw-edge",
          name: "Perimeter FortiGate",
          product: "FortiOS",
          version: "7.2.0",
          criticality: "critical",
          internetExposed: true,
          inventoryFreshness: "2026-10-01T00:00:00.000Z",
          lastSeenAt: "2026-10-01T00:00:00.000Z",
        },
        {
          id: "ledger-1",
          name: "Finance ledger",
          product: "ledger",
          criticality: "high",
        },
      ],
    });
    const claim = evaluateCustomerExposure({
      environment,
      products: [{ product: "FortiOS", version: "7.2.0" }],
      kev: true,
      now,
    });
    expect(claim.applicability).toBe("matched");
    expect(claim.relevance).not.toBeNull();
    expect(claim.relevance!).toBeGreaterThan(0);
    expect(claim.matchedAssetIds).toEqual(["fw-edge"]);
    expect(claim.wording.join(" ")).toMatch(/fw-edge/);
    expect(claim.wording.join(" ")).toMatch(/Inventory freshness/i);
    expect(claim.inventoryMayBeOutOfDate).toBe(false);
    // "edge" must not match "ledger"
    const noSubstring = evaluateCustomerExposure({
      environment,
      products: [{ product: "edge" }],
      now,
    });
    expect(noSubstring.applicability).toBe("unmatched");
    expect(noSubstring.matchedAssetIds).toEqual([]);
    expect(noSubstring.wording.join(" ").toLowerCase()).not.toContain(
      "your exposed asset",
    );
  });

  it("rejects version mismatch and warns when inventory is stale", () => {
    const environment = EnvironmentSchema.parse({
      assets: [
        {
          id: "fw-old",
          name: "Stale firewall",
          product: "FortiOS",
          version: "7.0.0",
          criticality: "high",
          inventoryFreshness: "2026-01-01T00:00:00.000Z",
          lastSeenAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    });
    const versionMiss = evaluateCustomerExposure({
      environment,
      products: [{ product: "FortiOS", version: "7.2.0" }],
      now,
    });
    expect(versionMiss.applicability).toBe("unmatched");
    expect(versionMiss.matchedAssetIds).toEqual([]);

    const staleMatch = evaluateCustomerExposure({
      environment,
      products: [{ product: "FortiOS", version: "7.0.0" }],
      now,
    });
    expect(staleMatch.applicability).toBe("matched");
    expect(staleMatch.inventoryMayBeOutOfDate).toBe(true);
    expect(staleMatch.wording.join(" ").toLowerCase()).toMatch(
      /inventory may be out of date/,
    );
  });

  it("surfaces SIEM/EDR sightings distinct from KEV and asset inventory", () => {
    const claim = evaluateCustomerExposure({
      environment: emptyEnv(),
      kev: true,
      observations: [
        {
          observableId: "obs-1",
          observedAt: "2026-10-12T12:00:00.000Z",
        },
      ],
    });
    expect(claim.hasSighting).toBe(true);
    expect(claim.wording.join(" ")).toMatch(/SIEM\/EDR sighting/i);
    expect(claim.wording.join(" ")).toMatch(/Known exploited vulnerability/i);
    expect(claim.applicability).toBe("unknown");
    expect(claim.relevance).toBeNull();
    expect(claim.wording.join(" ").toLowerCase()).not.toContain(
      "asset inventory",
    );
  });
});
