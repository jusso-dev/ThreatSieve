import { migrationStatements } from "../packages/database/src/migrations";
import {
  beforeAll,
  afterAll,
  afterEach,
  describe,
  it,
  expect,
  vi,
} from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { Repository } from "../packages/database/src/repository";
import { digest } from "../packages/intel/src/normalise";
import { correlate } from "../workers/correlate/index";
import type { Evidence } from "../packages/schemas/src/index";

let mf: Miniflare;
let db: D1Database;
let repo: Repository;

const T0 = "2026-01-01T00:00:00.000Z";
const provenance = (sourceId: string) => ({
  sourceId,
  sourceName: sourceId.toUpperCase(),
  retrievedAt: T0,
  redistributable: true,
});

async function addObservable(id: string, value: string) {
  await repo.putObservable(
    {
      id,
      type: "domain",
      value,
      normalizedValue: value,
      createdAt: T0,
      updatedAt: T0,
    },
    provenance("src-a"),
  );
}

async function addEvidence(
  e: Omit<Evidence, "provenance" | "behavioural" | "observableId"> & {
    observableId: string;
  },
) {
  await repo.putEvidence(e.observableId, {
    ...e,
    provenance: provenance(e.sourceId),
    behavioural: false,
  });
}

async function clusterRow() {
  return db
    .prepare("SELECT * FROM threat_clusters")
    .first<Record<string, string | number | null>>();
}

beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    d1Databases: ["DB"],
  });
  db = await mf.getD1Database("DB");
  repo = new Repository(db);
  for (const name of readdirSync("migrations").sort()) {
    const sql = readFileSync("migrations/" + name, "utf8");
    for (const statement of migrationStatements(sql))
      await db.prepare(statement).run();
  }
  await db
    .prepare(
      "INSERT INTO sources(id,name,independent_group,reliability,license) VALUES(?,?,?,?,?)",
    )
    .bind("src-a", "Source A", "independent", 1, "test")
    .run();
  await db
    .prepare(
      "INSERT INTO sources(id,name,independent_group,reliability,license) VALUES(?,?,?,?,?)",
    )
    .bind("src-b", "Source B", "independent", 1, "test")
    .run();
});
afterEach(() => {
  vi.useRealTimers();
});
afterAll(async () => {
  vi.useRealTimers();
  await mf?.dispose();
});

describe("cluster observation timestamps", () => {
  it("220-day-old evidence must not look fresh: bounds come from evidence observedAt, wall clock only fills last_processed_at", async () => {
    const observedAt = "2026-02-12T00:00:00.000Z";
    const processedMs = Date.parse(observedAt) + 220 * 86400000;
    vi.useFakeTimers();
    vi.setSystemTime(processedMs);
    await addObservable("obs-old", "old.example.test");
    await addEvidence({
      id: "old-ev",
      observableId: "obs-old",
      type: "malware",
      data: { malwareEntityId: "malware-family-old" },
      sourceId: "src-a",
      observedAt,
      confidence: 0.8,
      createdAt: observedAt,
    });
    await correlate(repo, "obs-old");
    const row = await clusterRow();
    const processedIso = new Date(processedMs).toISOString();
    expect(row?.first_observed).toBe(observedAt);
    expect(row?.last_observed).toBe(observedAt);
    expect(row?.first_seen).toBe(observedAt);
    expect(row?.last_seen).toBe(observedAt);
    expect(row?.last_seen).not.toBe(processedIso);
    expect(row?.last_processed_at).toBe(processedIso);
  });

  it("reprocessing identical old evidence leaves observation bounds unchanged", async () => {
    const observedAt = "2026-01-15T00:00:00.000Z";
    vi.useFakeTimers();
    vi.setSystemTime("2026-01-20T00:00:00.000Z");
    await addObservable("obs-reproc", "reproc.example.test");
    const evidence: Omit<
      Evidence,
      "provenance" | "behavioural" | "observableId"
    > & { observableId: string } = {
      id: "reproc-ev",
      observableId: "obs-reproc",
      type: "malware",
      data: { malwareEntityId: "malware-family-reproc" },
      sourceId: "src-a",
      observedAt,
      confidence: 0.8,
      createdAt: observedAt,
    };
    await addEvidence(evidence);
    await correlate(repo, "obs-reproc");
    const first = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-reproc'",
      )
      .first<Record<string, string | number | null>>();
    // Reprocess much later with identical evidence.
    vi.setSystemTime("2026-08-28T00:00:00.000Z");
    await addEvidence(evidence);
    await correlate(repo, "obs-reproc");
    const second = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-reproc'",
      )
      .first<Record<string, string | number | null>>();
    expect(second?.last_seen).toBe(observedAt);
    expect(second?.first_seen).toBe(observedAt);
    expect(second?.last_observed).toBe(observedAt);
    expect(second?.first_observed).toBe(observedAt);
    expect(second?.last_seen).toBe(first?.last_seen);
    expect(second?.last_processed_at).toBe("2026-08-28T00:00:00.000Z");
  });

  it("evidence without observation time stays unknown: bounds are null, never processing time", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-05-01T00:00:00.000Z");
    await addObservable("obs-unknown", "unknown.example.test");
    await addEvidence({
      id: "unknown-ev",
      observableId: "obs-unknown",
      type: "malware",
      data: { malwareEntityId: "malware-family-unknown" },
      sourceId: "src-a",
      confidence: 0.5,
      createdAt: "2026-05-01T00:00:00.000Z",
    });
    await correlate(repo, "obs-unknown");
    const row = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-unknown'",
      )
      .first<Record<string, string | number | null>>();
    expect(row?.first_observed).toBeNull();
    expect(row?.last_observed).toBeNull();
    expect(row?.first_seen).toBeNull();
    expect(row?.last_seen).toBeNull();
    expect(row?.last_processed_at).toBe("2026-05-01T00:00:00.000Z");
  });

  it("cluster name year derives from the earliest observation, not the processing date", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-10-01T00:00:00.000Z");
    await addObservable("obs-year", "year.example.test");
    await addEvidence({
      id: "year-ev",
      observableId: "obs-year",
      type: "malware",
      data: { malwareEntityId: "malware-family-year" },
      sourceId: "src-a",
      observedAt: "2025-11-05T00:00:00.000Z",
      confidence: 0.8,
      createdAt: "2025-11-05T00:00:00.000Z",
    });
    await correlate(repo, "obs-year");
    const row = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-year'",
      )
      .first<Record<string, string | number | null>>();
    expect(row?.name).toContain("TS-2025-");
  });
});

describe("cluster confidence and rationale", () => {
  it("confidence is recomputed from all member evidence, not frozen at the first writer's ev.confidence * 0.7", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-03-01T00:00:00.000Z");
    await addObservable("obs-c1", "c1.example.test");
    await addEvidence({
      id: "c1-ev",
      observableId: "obs-c1",
      type: "malware",
      data: { malwareEntityId: "malware-family-conf" },
      sourceId: "src-a",
      observedAt: "2026-02-20T00:00:00.000Z",
      confidence: 0.9,
      createdAt: "2026-02-20T00:00:00.000Z",
    });
    await correlate(repo, "obs-c1");
    const single = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-conf'",
      )
      .first<Record<string, string | number | null>>();
    expect(single?.confidence as number).toBeCloseTo(0.7 * 0.9, 10);

    // A second source with lower confidence joins the same cluster: the frozen
    // first-writer value (0.63) must not stick; the recomputed value is
    // 0.7 * (0.9 + 0.3) / 2 = 0.42.
    vi.setSystemTime("2026-03-02T00:00:00.000Z");
    await addObservable("obs-c2", "c2.example.test");
    await addEvidence({
      id: "c2-ev",
      observableId: "obs-c2",
      type: "malware",
      data: { malwareEntityId: "malware-family-conf" },
      sourceId: "src-b",
      observedAt: "2026-02-25T00:00:00.000Z",
      confidence: 0.3,
      createdAt: "2026-02-25T00:00:00.000Z",
    });
    await correlate(repo, "obs-c2");
    const pair = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-conf'",
      )
      .first<Record<string, string | number | null>>();
    expect(pair?.confidence as number).toBeCloseTo(0.7 * 0.6, 10);
    expect(pair?.confidence as number).not.toBeCloseTo(0.7 * 0.9, 2);
    expect(pair?.last_observed).toBe("2026-02-25T00:00:00.000Z");
    expect(pair?.first_observed).toBe("2026-02-20T00:00:00.000Z");
  });

  it("rationale records grouping kind, key and record/source counts in the pinned format", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-04-01T00:00:00.000Z");
    await addObservable("obs-r1", "r1.example.test");
    await addObservable("obs-r2", "r2.example.test");
    await addEvidence({
      id: "r1-ev",
      observableId: "obs-r1",
      type: "malware",
      data: { malwareEntityId: "malware-family-rationale" },
      sourceId: "src-a",
      observedAt: "2026-03-30T00:00:00.000Z",
      confidence: 0.8,
      createdAt: "2026-03-30T00:00:00.000Z",
    });
    await addEvidence({
      id: "r2-ev",
      observableId: "obs-r2",
      type: "malware",
      data: { malwareEntityId: "malware-family-rationale" },
      sourceId: "src-b",
      observedAt: "2026-03-31T00:00:00.000Z",
      confidence: 0.7,
      createdAt: "2026-03-31T00:00:00.000Z",
    });
    await correlate(repo, "obs-r1");
    await correlate(repo, "obs-r2");
    const row = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='malware:malware-family-rationale'",
      )
      .first<Record<string, string | number | null>>();
    expect(row?.rationale).toBe(
      "shared-malware malware:malware-family-rationale; 2 evidence records from 2 sources",
    );
    expect(row?.grouping_key).toBe("malware:malware-family-rationale");
  });

  it("shared-report and shared-certificate groupings carry their own rationale kind", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-04-02T00:00:00.000Z");
    await addObservable("obs-rep", "rep.example.test");
    await addEvidence({
      id: "rep-ev",
      observableId: "obs-rep",
      type: "threat-report",
      data: { reportId: "R-1" },
      sourceId: "src-a",
      observedAt: "2026-04-01T00:00:00.000Z",
      confidence: 0.8,
      createdAt: "2026-04-01T00:00:00.000Z",
    });
    await correlate(repo, "obs-rep");
    const report = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='report:src-a:R-1'",
      )
      .first<Record<string, string | number | null>>();
    expect(report?.rationale).toBe(
      "shared-report report:src-a:R-1; 1 evidence records from 1 sources",
    );

    await addObservable("obs-cert", "cert.example.test");
    await addEvidence({
      id: "cert-ev",
      observableId: "obs-cert",
      type: "certificate",
      data: { certificate: "cert-abc" },
      sourceId: "src-a",
      observedAt: "2026-04-01T00:00:00.000Z",
      confidence: 0.8,
      createdAt: "2026-04-01T00:00:00.000Z",
    });
    await correlate(repo, "obs-cert");
    const cert = await db
      .prepare(
        "SELECT * FROM threat_clusters WHERE grouping_key='certificate:cert-abc'",
      )
      .first<Record<string, string | number | null>>();
    expect(cert?.rationale).toBe(
      "shared-certificate certificate:cert-abc; 1 evidence records from 1 sources",
    );
  });

  it("shared malware association is labelled as association, not coordinated activity, and keeps the non-attribution disclaimer", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-04-03T00:00:00.000Z");
    await addObservable("obs-label", "label.example.test");
    await addEvidence({
      id: "label-ev",
      observableId: "obs-label",
      type: "malware",
      data: { malwareEntityId: "malware-family-label" },
      sourceId: "src-a",
      observedAt: "2026-04-01T00:00:00.000Z",
      confidence: 0.8,
      createdAt: "2026-04-01T00:00:00.000Z",
    });
    await correlate(repo, "obs-label");
    const id = "cluster_" + (await digest("malware:malware-family-label"));
    const entity = await repo.entity(id);
    expect(entity?.description).toContain("shared malware association");
    expect(entity?.description).toContain(
      "NOT evidence of coordinated activity",
    );
    expect(entity?.description).toContain(
      "This is not a confirmed campaign or actor attribution.",
    );
  });
});

describe("migration 0022 backfill", () => {
  it("backfills observation bounds from member evidence and leaves processing time unknown", async () => {
    const local = new Miniflare({
      modules: true,
      script: 'export default {fetch(){return new Response("ok")}}',
      compatibilityDate: "2026-08-06",
      d1Databases: ["DB"],
    });
    try {
      const ldb = await local.getD1Database("DB");
      const migrations = readdirSync("migrations").sort();
      const before = migrations.filter((n) => n < "0022");
      const run = (sql: string) =>
        migrationStatements(sql).reduce(
          (p, s) =>
            p.then(() =>
              ldb
                .prepare(s)
                .run()
                .then(() => undefined),
            ),
          Promise.resolve(),
        );
      for (const name of before)
        await run(readFileSync("migrations/" + name, "utf8"));
      const now = "2026-06-01T00:00:00.000Z";
      await ldb
        .prepare(
          "INSERT INTO sources(id,name,independent_group,reliability,license) VALUES('src-a','Source A','independent',1,'test')",
        )
        .run();
      // Seed the historical schema with its historical source assertion format.
      const lrepo = new (class extends Repository {
        override sourceStatements(
          e: Parameters<Repository["sourceStatements"]>[0],
        ) {
          return [
            this.db
              .prepare(
                "INSERT OR IGNORE INTO entity_sources(entity_id,source_id,source_record_id,provenance) VALUES(?,?,?,?)",
              )
              .bind(
                e.id,
                e.provenance.sourceId,
                e.provenance.sourceRecordId ?? e.id,
                JSON.stringify(e.provenance),
              ),
          ];
        }
      })(ldb);
      await lrepo.putObservable(
        {
          id: "obs-legacy",
          type: "domain",
          value: "legacy.example.test",
          normalizedValue: "legacy.example.test",
          createdAt: now,
          updatedAt: now,
        },
        {
          sourceId: "src-a",
          sourceName: "Source A",
          retrievedAt: now,
          redistributable: true,
        },
      );
      await lrepo.putEvidence("obs-legacy", {
        id: "legacy-ev",
        observableId: "obs-legacy",
        type: "malware",
        data: { malwareEntityId: "malware-family-legacy" },
        sourceId: "src-a",
        provenance: {
          sourceId: "src-a",
          sourceName: "Source A",
          retrievedAt: now,
          redistributable: true,
        },
        observedAt: "2026-01-10T00:00:00.000Z",
        confidence: 0.8,
        createdAt: now,
        behavioural: false,
      });
      // Legacy semantics: last_seen held processing time.
      await lrepo.putEntity({
        id: "cluster_legacy",
        type: "cluster",
        name: "Unknown Cluster TS-2026-LEGACY",
        description: "An evidence-linked cluster.",
        aliases: [],
        data: { signal: "malware:malware-family-legacy" },
        provenance: {
          sourceId: "src-a",
          sourceName: "Source A",
          retrievedAt: now,
          redistributable: true,
        },
      });
      await ldb
        .prepare(
          "INSERT INTO threat_clusters(id,name,status,first_seen,last_seen,confidence) VALUES('cluster_legacy','Unknown Cluster TS-2026-LEGACY','emerging','2026-01-10T00:00:00.000Z',?,0.56)",
        )
        .bind(now)
        .run();
      await ldb
        .prepare(
          "INSERT INTO cluster_members VALUES('cluster_legacy','obs-legacy','legacy-ev')",
        )
        .run();

      await run(
        readFileSync("migrations/0026_cluster_observation.sql", "utf8"),
      );
      const row = await ldb
        .prepare("SELECT * FROM threat_clusters WHERE id='cluster_legacy'")
        .first<Record<string, string | number | null>>();
      expect(row?.first_observed).toBe("2026-01-10T00:00:00.000Z");
      expect(row?.last_observed).toBe("2026-01-10T00:00:00.000Z");
      expect(row?.last_seen).toBe("2026-01-10T00:00:00.000Z");
      expect(row?.first_seen).toBe("2026-01-10T00:00:00.000Z");
      expect(row?.last_processed_at).toBeNull();
      expect(row?.grouping_key).toBe("malware:malware-family-legacy");
      expect(row?.rationale).toBe(
        "shared-malware malware:malware-family-legacy; 1 evidence records from 1 sources",
      );
    } finally {
      await local.dispose();
    }
  });
});

it("correlation observation bounds exclude future evidence while retaining valid observations", async () => {
  vi.useFakeTimers();
  vi.setSystemTime("2026-10-16T00:00:00.000Z");
  await addObservable("obs-future-boundary", "future-boundary.example.test");
  const data = { malwareEntityId: "malware-future-boundary" };
  for (const [id, observedAt, sourceId] of [
    ["valid-boundary-evidence", "2026-10-15T00:00:00.000Z", "src-a"],
    ["future-boundary-evidence", "2027-01-01T00:00:00.000Z", "src-b"],
  ]) {
    await addEvidence({
      id: id!,
      observableId: "obs-future-boundary",
      type: "malware",
      sourceId: sourceId!,
      data,
      observedAt,
      confidence: 0.9,
      createdAt: T0,
    });
  }
  await correlate(repo, "obs-future-boundary");
  const id = "cluster_" + (await digest("malware:malware-future-boundary"));
  expect(
    await db
      .prepare(
        "SELECT first_observed,last_observed,last_processed_at FROM threat_clusters WHERE id=?",
      )
      .bind(id)
      .first(),
  ).toEqual({
    first_observed: "2026-10-15T00:00:00.000Z",
    last_observed: "2026-10-15T00:00:00.000Z",
    last_processed_at: "2026-10-16T00:00:00.000Z",
  });
});
