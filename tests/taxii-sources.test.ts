import { afterAll, beforeAll, expect, it } from "vitest";
import type { Miniflare } from "miniflare";
import { migratedDatabase } from "./hub-fixtures";
import { getFeed } from "../workers/feed-sync/index";
import {
  ensureTaxiiSources,
  taxiiSourceConfigs,
  tlpOf,
} from "../packages/intel/src/taxii-sources";
import type { AppEnv } from "../apps/api/src/env";
import type { OptionalFeed } from "../packages/intel/src/optional-feeds";

const GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da";
const AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82";
const CLEAR2 = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487";
const RED2 = "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1";
const indicator = (n: number, markings?: string[]) => ({
  type: "indicator",
  spec_version: "2.1",
  id: "indicator--00000000-0000-4000-8000-00000000000" + n,
  created: "2099-01-01T00:00:00.000Z",
  modified: "2099-01-01T00:00:00.000Z",
  pattern: "[ipv4-addr:value = '198.51.100." + n + "']",
  pattern_type: "stix",
  valid_from: "2099-01-01T00:00:00.000Z",
  created_by_ref: "identity--11111111-1111-4111-8111-111111111111",
  ...(markings ? { object_marking_refs: markings } : {}),
});
const sources = [
  {
    id: "taxii-foiled",
    name: "Foiled (TAXII 2.1)",
    endpoint: "https://foiled.example.test/taxii2/foiled/",
    collection: "honeypot-clear-green",
    allowed_host: "foiled.example.test",
    api_key_secret: "TAXII_FOILED_API_KEY",
    license: "Foiled honeypot intelligence, operator terms",
  },
  {
    id: "taxii-partner",
    name: "Partner TAXII",
    endpoint: "https://partner.example.test/api/collections/abc/objects/",
    allowed_host: "partner.example.test",
    api_key_secret: "TAXII_PARTNER_TOKEN",
    tlp: ["white", "green", "amber", "unmarked"],
    page_limit: 50,
    schedule: "daily",
    // Operators can still keep a partner feed out of exports.
    redistributable: false,
  },
  {
    id: "not-taxii",
    name: "Invalid",
    endpoint: "https://x.test/",
    allowed_host: "x.test",
  },
];
let mf: Miniflare;
let db: D1Database;
beforeAll(async () => {
  ({ mf, db } = await migratedDatabase());
}, 120000);
afterAll(async () => {
  await mf?.dispose();
});

it("classifies standard TLP 1.0 and 2.0 markings, most restrictive first", () => {
  expect(tlpOf(indicator(1))).toBe("unmarked");
  expect(tlpOf(indicator(1, [GREEN]))).toBe("green");
  expect(tlpOf(indicator(1, [CLEAR2, AMBER]))).toBe("amber");
  expect(tlpOf(indicator(1, ["marking-definition--custom", RED2]))).toBe("red");
});

it("runs two configured TAXII sources beside the original slot", async () => {
  const calls: { url: string; auth: string | null }[] = [];
  const objects = [
    indicator(1, [CLEAR2]),
    indicator(2, [GREEN]),
    indicator(3, [AMBER]),
    indicator(4),
    indicator(5, [RED2]),
  ];
  const env = {
    DB: db,
    TAXII_SOURCES: JSON.stringify(sources),
    TAXII_FOILED_API_KEY: "test-foiled-reader",
    TAXII_PARTNER_TOKEN: "test-partner-reader",
    TAXII_ENABLED: "true",
    TAXII_ENDPOINT:
      "https://opencti.example.test/taxii2/root/collections/c/objects/",
    TAXII_ALLOWED_HOST: "opencti.example.test",
    TAXII_API_KEY: "test-opencti-reader",
  } as unknown as AppEnv;
  const configs = taxiiSourceConfigs(env);
  expect(configs.map((c) => c.id)).toEqual(["taxii-foiled", "taxii-partner"]);
  await ensureTaxiiSources(db, configs);
  await ensureTaxiiSources(db, configs);
  const rows = await db
    .prepare(
      "SELECT id,independent_group,license,redistributable,commercial_use,enabled FROM sources WHERE id LIKE 'taxii%' ORDER BY id",
    )
    .all();
  expect(rows.results).toEqual([
    {
      id: "taxii",
      independent_group: "taxii",
      license: "Provider terms",
      redistributable: 1,
      commercial_use: null,
      enabled: 0,
    },
    {
      id: "taxii-foiled",
      independent_group: "taxii-foiled",
      license: "Foiled honeypot intelligence, operator terms",
      redistributable: 1,
      commercial_use: null,
      enabled: 1,
    },
    {
      id: "taxii-partner",
      independent_group: "taxii-partner",
      license: "Provider terms",
      redistributable: 0,
      commercial_use: null,
      enabled: 1,
    },
  ]);
  const request: typeof fetch = async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    calls.push({
      url,
      auth: new Headers(init?.headers).get("Authorization"),
    });
    return Response.json({ objects, more: false });
  };
  const imported: Record<string, string[]> = {};
  for (const id of ["taxii-foiled", "taxii-partner", "taxii"]) {
    const feed = getFeed(env, id) as OptionalFeed;
    // Swap in the offline transport.
    (feed as unknown as { request: typeof fetch }).request = request;
    expect((await feed.healthCheck()).status).toBe("healthy");
    const batch = await feed.fetch();
    imported[id] = [];
    for (const record of batch.records)
      for (const r of await feed.normalize(record)) {
        imported[id]!.push(r.observable!.value);
        expect(r.provenance).toMatchObject({
          sourceId: id,
          redistributable: id !== "taxii-partner",
          originalSourceId: "identity--11111111-1111-4111-8111-111111111111",
        });
      }
  }
  expect(
    calls.map((c) => [
      new URL(c.url).origin + new URL(c.url).pathname,
      new URL(c.url).searchParams.get("limit"),
      c.auth,
    ]),
  ).toEqual([
    [
      "https://foiled.example.test/taxii2/foiled/collections/honeypot-clear-green/objects/",
      "100",
      "Bearer test-foiled-reader",
    ],
    [
      "https://partner.example.test/api/collections/abc/objects/",
      "50",
      "Bearer test-partner-reader",
    ],
    [
      "https://opencti.example.test/taxii2/root/collections/c/objects/",
      "100",
      "Bearer test-opencti-reader",
    ],
  ]);
  // Default allow-list is TLP:CLEAR and TLP:GREEN; unmarked objects are skipped.
  expect(imported["taxii-foiled"]).toEqual(["198.51.100.1", "198.51.100.2"]);
  expect(imported["taxii-partner"]).toEqual([
    "198.51.100.1",
    "198.51.100.2",
    "198.51.100.3",
    "198.51.100.4",
  ]);
  // The original slot keeps its behaviour: no marking filter.
  expect(imported.taxii).toHaveLength(5);
});

it("keeps a source disabled until its named token exists", async () => {
  const env = {
    DB: db,
    TAXII_SOURCES: JSON.stringify(sources.slice(0, 1)),
  } as unknown as AppEnv;
  expect((await getFeed(env, "taxii-foiled").healthCheck()).status).toBe(
    "disabled",
  );
  expect(() => getFeed(env, "taxii-unknown")).toThrow(/unavailable/);
  expect(
    taxiiSourceConfigs({
      TAXII_SOURCES: JSON.stringify([
        { ...sources[0], api_key_secret: "BETTER_AUTH_SECRET" },
      ]),
    }),
  ).toEqual([]);
  expect(taxiiSourceConfigs({ TAXII_SOURCES: "not json" })).toEqual([]);
});
