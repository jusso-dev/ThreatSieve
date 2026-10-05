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
    for (const sql of readFileSync("migrations/" + name, "utf8")
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean))
      await db.prepare(sql).run();
});
afterAll(async () => {
  await mf?.dispose();
});
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
        .prepare("SELECT COUNT(*) AS n FROM entity_sources")
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
