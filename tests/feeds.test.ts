import { migrationStatements } from "../packages/database/src/migrations";
import { beforeAll, afterAll, it, expect, vi } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { Repository } from "../packages/database/src/repository";
import { AdditionalFeed } from "../packages/intel/src/additional-feeds";
import { OptionalFeed } from "../packages/intel/src/optional-feeds";
import {
  PublicFeed,
  boundedText,
  stixRecord,
} from "../packages/intel/src/feeds";
import { ingestRecord } from "../packages/intel/src/ingest";
import { normalise } from "../packages/intel/src/normalise";
import { getFeed } from "../workers/feed-sync/index";
import type { AppEnv } from "../apps/api/src/env";
import type { IntelEntity } from "../packages/schemas/src/index";
let mf: Miniflare;
let repo: Repository;
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  const db = await mf.getD1Database("DB");
  repo = new Repository(db);
  for (const name of readdirSync("migrations").sort())
    for (const sql of migrationStatements(
      readFileSync("migrations/" + name, "utf8"),
    ))
      await db.prepare(sql).run();
});
afterAll(async () => {
  await mf?.dispose();
});
it.each([
  ["vulnerability", "CVE-2026-99998"],
  ["attack-technique", "T9998"],
  ["attack-tactic", "TA9998"],
] as const)(
  "attaches re-keyed %s records to the canonical entity without replacing it",
  async (type, externalId) => {
    const entity: IntelEntity = {
      id: "canonical-" + type,
      type,
      externalId,
      name: externalId,
      description: "Original intelligence",
      aliases: [],
      data: {},
      provenance: {
        sourceId: "mitre",
        sourceName: "Original",
        retrievedAt: new Date().toISOString(),
        redistributable: true,
      },
    };
    await repo.putEntity(entity);
    const imported = {
      ...entity,
      id: "secondary-" + type,
      description: "Secondary copy",
      aliases: ["Imported " + type],
      provenance: {
        ...entity.provenance,
        sourceId: "taxii",
        sourceName: "TAXII",
      },
    };
    const input = {
      entity: imported,
      provenance: imported.provenance,
      evidence: [],
      relationships: [],
    };
    expect(await ingestRecord(repo, input)).toBe(entity.id);
    expect(await ingestRecord(repo, input)).toBe(entity.id);
    expect(await repo.entity(entity.id)).toEqual(entity);
    expect(await repo.entity(imported.id)).toBeNull();
    expect((await repo.resolveAlias(imported.aliases[0]!, type))[0]?.id).toBe(
      entity.id,
    );
    expect(
      await repo.db
        .prepare("SELECT COUNT(*) AS n FROM entity_sources WHERE entity_id=?")
        .bind(entity.id)
        .first(),
    ).toEqual({ n: 2 });
  },
);
it("routes approved TAXII requests through the private binding and retains request safeguards", async () => {
  const request = vi
    .fn()
    .mockImplementation(async () =>
      Response.json({ objects: [], more: false }),
    );
  const env = {
    DB: repo.db,
    OPENCTI_VPC: { fetch: request },
    TAXII_ENABLED: "true",
    TAXII_ENDPOINT: "https://opencti.example.test/taxii/objects/",
    TAXII_ALLOWED_HOST: "opencti.example.test",
    TAXII_API_KEY: "test-only",
    TAXII_PAGE_LIMIT: "25",
  } as unknown as AppEnv;
  await getFeed(env, "taxii").fetch();
  const [url, init] = request.mock.calls[0]!;
  expect(String(url)).toBe(
    "http://opencti.example.test/taxii/objects/?limit=25",
  );
  expect(init).toMatchObject({
    redirect: "manual",
    headers: { Authorization: "Bearer test-only" },
  });
  request.mockClear();
  await expect(
    getFeed(
      {
        ...env,
        TAXII_ENDPOINT: "https://unapproved.example.test/",
      } as AppEnv,
      "taxii",
    ).fetch(),
  ).rejects.toThrow("approved HTTPS");
  expect(request).not.toHaveBeenCalled();
  request.mockResolvedValueOnce(
    new Response(null, {
      status: 302,
      headers: { Location: "https://unapproved.example.test/" },
    }),
  );
  await expect(getFeed(env, "taxii").fetch()).rejects.toThrow("302");
});
it.each([undefined, 0, 1001, NaN, 2.5, 25])(
  "bounds the TAXII page limit (%s)",
  async (pageLimit) => {
    const request = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json({ objects: [] }));
    const feed = new OptionalFeed(
      "taxii",
      "TAXII",
      repo,
      {
        enabled: true,
        endpoint: "https://approved.example.test/objects/",
        allowedHost: "approved.example.test",
        pageLimit,
      },
      request,
    );
    await feed.fetch();
    expect(
      new URL(String(request.mock.calls[0]![0])).searchParams.get("limit"),
    ).toBe(pageLimit === 25 ? "25" : "100");
  },
);
it("resolves MISP aliases to an explicit MITRE canonical group without inventing attribution", async () => {
  const provenance = {
    sourceId: "mitre",
    sourceName: "MITRE ATT&CK",
    retrievedAt: new Date().toISOString(),
    redistributable: true,
  };
  for (const r of await stixRecord(
    {
      id: "intrusion-set--11111111-1111-4111-8111-111111111111",
      type: "intrusion-set",
      name: "APT28",
      external_references: [
        { source_name: "mitre-attack", external_id: "G0007" },
      ],
    },
    provenance,
  ))
    await ingestRecord(repo, r);
  const feed = new AdditionalFeed("misp", "MISP Galaxy", repo);
  for (const record of await feed.normalize({
    uuid: "galaxy-1",
    value: "APT28",
    collection: "threat-actor",
    meta: {
      synonyms: ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
      refs: ["https://attack.mitre.org/groups/G0007/"],
    },
  }))
    await ingestRecord(repo, record);
  for (const name of ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"])
    expect((await repo.resolveAlias(name, "threat-actor"))[0]?.externalId).toBe(
      "G0007",
    );
  expect(
    (
      await repo.db
        .prepare(
          "SELECT COUNT(*) AS n FROM entity_sources WHERE entity_id='intrusion-set--11111111-1111-4111-8111-111111111111'",
        )
        .first<{ n: number }>()
    )?.n,
  ).toBe(2);
});
it("imports CISA exposure fields without asserting a CVE is malicious", async () => {
  const feed = new AdditionalFeed("cisa-kev", "CISA KEV", repo);
  const records = await feed.normalize({
    cveID: "CVE-2024-99999",
    vendorProject: "Demo vendor",
    product: "Demo product",
    vulnerabilityName: "Synthetic KEV case",
    dateAdded: "2026-10-01",
    shortDescription: "Test vulnerability",
    requiredAction: "Apply mitigation",
    dueDate: "2026-10-20",
    knownRansomwareCampaignUse: "Unknown",
    notes: "Synthetic test",
  });
  for (const r of records) await ingestRecord(repo, r);
  const evidence = await repo.evidence((await normalise("CVE-2024-99999")).id);
  expect(evidence[0]?.data.kev).toBe(true);
  expect(evidence[0]?.data.malicious).toBeUndefined();
  expect(evidence[0]?.data.dueDate).toBe("2026-10-20");
});
it("does not propagate URLhaus URL maliciousness to its shared host", async () => {
  const feed = new AdditionalFeed("urlhaus", "URLhaus", repo);
  for (const r of await feed.normalize({
    id: 42,
    url: "https://delivery.example.test/payload",
    date_added: "2026-10-04 01:00:00",
    tags: ["test"],
    payloads: [{ response_sha256: "b".repeat(64), signature: "DemoRAT" }],
  }))
    await ingestRecord(repo, r);
  expect(
    (await repo.evidence((await normalise("delivery.example.test")).id)).length,
  ).toBe(0);
  expect(
    (await repo.evidence((await normalise("b".repeat(64))).id))[0]?.data
      .signature,
  ).toBe("DemoRAT");
});
it("preserves Feodo port and source-provided malware association", async () => {
  const feed = new AdditionalFeed("feodo", "Feodo Tracker", repo);
  for (const r of await feed.normalize({
    ip_address: "192.0.2.22",
    port: 443,
    malware: "SyntheticBot",
    first_seen: "2026-10-03T00:00:00Z",
    last_online: "2026-10-05",
  }))
    await ingestRecord(repo, r);
  const e = (await repo.evidence((await normalise("192.0.2.22")).id))[0];
  expect(e?.data.port).toBe(443);
  expect(e?.data.malware).toBe("SyntheticBot");
  expect(e?.behavioural).toBe(false);
});
it("requires feed keys, uses fixed URLs and fails cleanly on upstream rejection", async () => {
  const noKey = new PublicFeed("threatfox", "ThreatFox", repo);
  expect((await noKey.healthCheck()).status).toBe("disabled");
  await expect(noKey.fetch()).rejects.toThrow("credential");
  const request = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("bad", { status: 503 }));
  const feed = new PublicFeed(
    "threatfox",
    "ThreatFox",
    repo,
    { THREATFOX_AUTH_KEY: "test-only" },
    request,
  );
  await expect(feed.fetch()).rejects.toThrow("503");
  expect(request.mock.calls[0]?.[0]).toBe(
    "https://threatfox-api.abuse.ch/api/v1/",
  );
});
it("enforces streaming size limits without trusting Content-Length", async () => {
  await expect(boundedText(new Response("123456"), 5)).rejects.toThrow(
    "size limit",
  );
});
it("keeps optional feeds disabled and rejects custom endpoint SSRF", async () => {
  const feed = new OptionalFeed("otx", "OTX", repo, { enabled: false });
  expect((await feed.healthCheck()).status).toBe("disabled");
  await expect(feed.fetch()).rejects.toThrow("disabled");
  const unsafe = new OptionalFeed("taxii", "TAXII", repo, {
    enabled: true,
    endpoint: "http://127.0.0.1/private",
    allowedHost: "127.0.0.1",
  });
  await expect(unsafe.fetch()).rejects.toThrow("approved HTTPS");
});
it("rejects redirects without forwarding feed credentials to another host", async () => {
  const request = vi.fn<typeof fetch>().mockResolvedValue(
    new Response(null, {
      status: 302,
      headers: { Location: "https://untrusted.invalid/collect" },
    }),
  );
  const providers = [
    new PublicFeed(
      "threatfox",
      "ThreatFox",
      repo,
      { THREATFOX_AUTH_KEY: "test-only" },
      request,
    ),
    new AdditionalFeed(
      "urlhaus",
      "URLhaus",
      repo,
      { URLHAUS_AUTH_KEY: "test-only" },
      request,
    ),
    new OptionalFeed(
      "stix",
      "Approved STIX",
      repo,
      {
        enabled: true,
        endpoint: "https://approved.invalid/stix",
        allowedHost: "approved.invalid",
        apiKey: "test-only",
      },
      request,
    ),
  ];
  for (const provider of providers)
    await expect(provider.fetch()).rejects.toThrow("302");
  expect(request).toHaveBeenCalledTimes(3);
  for (const [, init] of request.mock.calls)
    expect(init?.redirect).toBe("manual");
});
