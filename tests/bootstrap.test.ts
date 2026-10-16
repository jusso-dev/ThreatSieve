import { expect, it } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { migrationStatements } from "../packages/database/src/migrations";
import { buildDemoSeed } from "../scripts/demo-data";

it("bootstrap seed applies to the current schema with complete source identities", async () => {
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  try {
    const db = await mf.getD1Database("DB");
    for (const name of readdirSync("migrations").sort())
      for (const sql of migrationStatements(
        readFileSync("migrations/" + name, "utf8"),
      ))
        await db.prepare(sql).run();
    const seed = await buildDemoSeed();
    for (let i = 0; i < seed.statements.length; i += 50)
      await db.batch(
        seed.statements.slice(i, i + 50).map((sql) => db.prepare(sql)),
      );
    const sources = await db
      .prepare(
        "SELECT source_id,record_namespace,original_source_id FROM entity_sources",
      )
      .all<{
        source_id: string;
        record_namespace: string;
        original_source_id: string;
      }>();
    expect(sources.results.length).toBeGreaterThan(0);
    expect(
      sources.results.every(
        (p) =>
          p.source_id === "demo" &&
          p.record_namespace === "demo" &&
          p.original_source_id === "demo",
      ),
    ).toBe(true);
    expect(
      (await db.prepare("PRAGMA foreign_key_check").all()).results,
    ).toEqual([]);
  } finally {
    await mf.dispose();
  }
});
