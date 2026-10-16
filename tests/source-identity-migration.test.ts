import { expect, it } from "vitest";
import { Miniflare } from "miniflare";
import { readdirSync, readFileSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";

it("namespace migration preserves existing assertions and permits distinct provider namespaces", async () => {
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  try {
    const db = await mf.getD1Database("DB");
    for (const name of readdirSync("migrations")
      .sort()
      .filter((n) => n < "0031"))
      for (const sql of migrationStatements(
        readFileSync("migrations/" + name, "utf8"),
      ))
        await db.prepare(sql).run();
    const p = {
      sourceId: "mitre",
      sourceName: "MITRE",
      sourceRecordId: "42",
      retrievedAt: "2026-10-16T00:00:00.000Z",
      redistributable: true,
    };
    await db
      .prepare(
        "INSERT INTO entities(id,type,name,data,created_at,updated_at) VALUES('migration-source','campaign','Migration fixture','{}','2026-10-16T00:00:00.000Z','2026-10-16T00:00:00.000Z')",
      )
      .run();
    await db
      .prepare(
        "INSERT INTO entity_sources VALUES('migration-source','mitre','42',?)",
      )
      .bind(JSON.stringify(p))
      .run();
    for (const sql of migrationStatements(
      readFileSync("migrations/0031_source_identity.sql", "utf8"),
    ))
      await db.prepare(sql).run();
    expect(
      (
        await db
          .prepare("SELECT COUNT(*) AS n FROM entity_sources")
          .first<{ n: number }>()
      )?.n,
    ).toBe(1);
    expect(
      await db
        .prepare(
          "SELECT record_namespace,original_source_id FROM entity_sources",
        )
        .first(),
    ).toEqual({ record_namespace: "mitre", original_source_id: "mitre" });
    await db
      .prepare(
        "INSERT INTO entity_sources VALUES('migration-source','mitre','42',?,'another-original','another-original')",
      )
      .bind(
        JSON.stringify({
          ...p,
          sourceRecordNamespace: "another-original",
          originalSourceId: "another-original",
        }),
      )
      .run();
    expect(
      (
        await db
          .prepare("SELECT COUNT(*) AS n FROM entity_sources")
          .first<{ n: number }>()
      )?.n,
    ).toBe(2);
    expect(
      (await db.prepare("PRAGMA foreign_key_check").all()).results,
    ).toEqual([]);
  } finally {
    await mf.dispose();
  }
});
