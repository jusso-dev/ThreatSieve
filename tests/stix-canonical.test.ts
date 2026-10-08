import { afterAll, beforeAll, expect, it } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { Repository } from "../packages/database/src/repository";
import { ingestRecord } from "../packages/intel/src/ingest";
import { stixRecord } from "../packages/intel/src/feeds";
import { entityId } from "../packages/intel/src/normalise";
let mf: Miniflare;
let db: D1Database;
let repo: Repository;
beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  repo = new Repository(db);
  for (const name of readdirSync("migrations").sort())
    for (const statement of migrationStatements(
      readFileSync("migrations/" + name, "utf8"),
    ))
      await db.prepare(statement).run();
});
afterAll(() => mf.dispose());
const taxii = {
  sourceId: "taxii",
  sourceName: "TAXII 2.1",
  retrievedAt: new Date().toISOString(),
  redistributable: false,
};
it("merges a re-keyed STIX CVE into the KEV entity without overwriting it", async () => {
  const kevId = await entityId("vulnerability", "CVE-2026-0001");
  await ingestRecord(repo, {
    entity: {
      id: kevId,
      type: "vulnerability",
      name: "CVE-2026-0001",
      externalId: "CVE-2026-0001",
      description: "KEV record",
      aliases: [],
      data: { vendorProject: "Vendor", product: "Product" },
      provenance: { ...taxii, sourceId: "cisa-kev", sourceName: "CISA KEV" },
    },
    provenance: { ...taxii, sourceId: "cisa-kev", sourceName: "CISA KEV" },
    relationships: [],
    evidence: [],
  });
  const [record] = await stixRecord(
    {
      type: "vulnerability",
      spec_version: "2.1",
      id: "vulnerability--a8db3bd3-f319-58d3-a515-36a1eab1bb45",
      created: "2026-10-06T00:00:00.000Z",
      modified: "2026-10-06T00:00:00.000Z",
      name: "CVE-2026-0001",
      description: "OpenCTI copy",
    },
    taxii,
  );
  expect(await ingestRecord(repo, record!)).toBe(kevId);
  const vulns = await db
    .prepare("SELECT entity_id,kev,vendor FROM vulnerabilities WHERE cve=?")
    .bind("CVE-2026-0001")
    .all();
  expect(vulns.results).toEqual([
    { entity_id: kevId, kev: 1, vendor: "Vendor" },
  ]);
  const entity = await repo.entity(kevId);
  expect(entity?.description).toBe("KEV record");
  const sources = await db
    .prepare(
      "SELECT source_id FROM entity_sources WHERE entity_id=? ORDER BY source_id",
    )
    .bind(kevId)
    .all();
  expect(sources.results.map((r) => r.source_id)).toEqual([
    "cisa-kev",
    "taxii",
  ]);
});
