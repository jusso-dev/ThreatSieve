import { expect, it } from "vitest";
import { Miniflare } from "miniflare";
import { readdirSync, readFileSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";

it("open-feed migration makes feed records redistributable and leaves tenant-private records private", async () => {
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  try {
    const db = await mf.getD1Database("DB");
    const run = async (filter: (name: string) => boolean) => {
      for (const name of readdirSync("migrations").sort().filter(filter))
        for (const sql of migrationStatements(
          readFileSync("migrations/" + name, "utf8"),
        ))
          await db.prepare(sql).run();
    };
    await run((n) => n < "0037");
    const at = "2026-10-22T00:00:00.000Z";
    const provenance = (sourceId: string) =>
      JSON.stringify({
        sourceId,
        sourceName: sourceId,
        retrievedAt: at,
        redistributable: false,
      });
    for (const [id, source] of [
      ["feed-entity", "threatfox"],
      ["private-entity", "customer"],
    ] as const) {
      await db
        .prepare(
          "INSERT INTO entities(id,type,name,data,created_at,updated_at) VALUES(?,'malware',?,?,?,?)",
        )
        .bind(
          id,
          id,
          JSON.stringify({ id, provenance: JSON.parse(provenance(source)) }),
          at,
          at,
        )
        .run();
      await db
        .prepare(
          "INSERT INTO evidence(id,entity_id,source_id,data,created_at) VALUES(?,?,?,?,?)",
        )
        .bind(
          "ev-" + id,
          id,
          source,
          JSON.stringify({ provenance: JSON.parse(provenance(source)) }),
          at,
        )
        .run();
      await db
        .prepare(
          "INSERT INTO relationships(id,source_entity_id,target_entity_id,relationship_type,assertion_type,confidence,source_id,data,created_at) VALUES(?,?,?,'USES','source_claimed',0.5,?,?,?)",
        )
        .bind(
          "rel-" + id,
          id,
          id,
          source,
          JSON.stringify({ provenance: JSON.parse(provenance(source)) }),
          at,
        )
        .run();
      await db
        .prepare(
          "INSERT INTO entity_sources(entity_id,source_id,source_record_id,provenance,record_namespace,original_source_id) VALUES(?,?,?,?,?,?)",
        )
        .bind(id, source, "1", provenance(source), source, source)
        .run();
    }
    await run((n) => n.startsWith("0037"));

    const flags = await db
      .prepare(
        "SELECT e.id, json_extract(e.data,'$.provenance.redistributable') AS entity, json_extract(v.data,'$.provenance.redistributable') AS evidence, json_extract(r.data,'$.provenance.redistributable') AS relationship, json_extract(s.provenance,'$.redistributable') AS assertion FROM entities e JOIN evidence v ON v.entity_id=e.id JOIN relationships r ON r.source_entity_id=e.id JOIN entity_sources s ON s.entity_id=e.id ORDER BY e.id",
      )
      .all();
    expect(flags.results).toEqual([
      {
        id: "feed-entity",
        entity: 1,
        evidence: 1,
        relationship: 1,
        assertion: 1,
      },
      {
        id: "private-entity",
        entity: 0,
        evidence: 0,
        relationship: 0,
        assertion: 0,
      },
    ]);
    const sources = await db
      .prepare("SELECT id FROM sources WHERE redistributable=0 ORDER BY id")
      .all<{ id: string }>();
    expect(sources.results.map((s) => s.id)).toEqual([
      "analyst",
      "customer",
      "upload",
    ]);
  } finally {
    await mf.dispose();
  }
});
