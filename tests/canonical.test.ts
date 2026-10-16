import { migrationStatements } from "../packages/database/src/migrations";
import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { Repository } from "../packages/database/src/repository";
import {
  aliasEntity,
  annotateMirroredAssertions,
  browseCanonicalEntities,
  canonicalEntities,
  latestAssessmentPerObservable,
  identityGroup,
  unaliasEntity,
} from "../packages/database/src/canonical";
import type {
  Assessment,
  IntelEntity,
  Principal,
} from "../packages/schemas/src/index";

let mf: Miniflare;
let db: D1Database;
let repo: Repository;

const principal: Principal = {
  tenantId: "tenant-canonical",
  userId: "analyst-a",
  keyId: "key-a",
  scopes: ["admin"],
  kind: "key",
};

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
    .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
    .bind(principal.tenantId, "Canonical Tenant", new Date().toISOString())
    .run();
  for (const [id, name, group] of [
    ["mitre", "MITRE ATT&CK", "mitre"],
    ["taxii", "TAXII Mirror", "taxii-redistributor"],
    ["misp", "MISP Mirror", "misp-redistributor"],
  ] as const)
    await db
      .prepare(
        "INSERT OR IGNORE INTO sources(id,name,independent_group,reliability,license) VALUES(?,?,?,?,?)",
      )
      .bind(id, name, group, 0.9, "test")
      .run();
});
afterAll(async () => {
  await mf?.dispose();
});

function campaign(
  id: string,
  sourceId: string,
  sourceName: string,
  sourceRecordId: string,
): IntelEntity {
  const now = new Date().toISOString();
  return {
    id,
    type: "campaign",
    name: "Operation Mirror",
    description: "Shared campaign across redistributors",
    aliases: ["op-mirror"],
    externalId: "campaign--mirror-1",
    data: {},
    provenance: {
      sourceId,
      sourceName,
      sourceRecordId,
      sourceRecordNamespace: "test-shared-origin",
      originalSourceId: "test-shared-origin",
      retrievedAt: now,
      redistributable: true,
    },
  };
}

function modelAssessment(
  id: string,
  observableId: string,
  createdAt: string,
  overrides: Partial<Assessment> = {},
): Assessment {
  return {
    schema_version: "1.0",
    assessment_id: id,
    observable: {
      id: observableId,
      type: "cve",
      value: "CVE-2024-CANON",
      normalizedValue: "cve-2024-canon",
      createdAt,
      updatedAt: createdAt,
    },
    malicious: { probability: 0.8, classification: "malicious" },
    role: { value: "exploit", probability: 0.7 },
    severity: "high",
    confidence: 0.7,
    confidence_factors: [],
    attack: [],
    actors: [],
    malware: [],
    customer: {
      relevance: 0.5,
      priority: "medium",
      reasons: [],
      exposedAssets: 0,
      observed: false,
    },
    recommended_actions: [
      { action: "investigate", confidence: 0.7, reason_codes: [] },
    ],
    human_review: false,
    human_review_probability: 0.2,
    evidence: [],
    sources: [],
    reason_codes: [],
    models: {
      classifier: "clef-flash",
      schema_version: "1.0",
      question_set_version: "q1",
    },
    runs: [],
    evidence_version: "v1",
    created_at: createdAt,
    status: "pending",
    demo: true,
    ...overrides,
  };
}

it("shared source records identify assertions without merging different entity types or different observables", async () => {
  const record = "shared-association-record";
  const original = {
    ...campaign("identity-campaign", "mitre", "MITRE", record),
    name: "Association identity regression",
    externalId: "shared-association-external",
  };
  await repo.putEntity(original);
  await repo.putEntity({
    ...original,
    id: "identity-malware",
    type: "malware",
  });
  for (const id of ["identity-observable-a", "identity-observable-b"]) {
    await repo.putObservable(
      {
        id,
        type: "domain",
        value: id + ".example",
        normalizedValue: id + ".example",
        createdAt: original.provenance.retrievedAt,
        updatedAt: original.provenance.retrievedAt,
      },
      original.provenance,
    );
  }
  for (const id of [
    "identity-campaign",
    "identity-malware",
    "identity-observable-a",
    "identity-observable-b",
  ]) {
    expect(
      (await identityGroup(repo, principal.tenantId, id))?.memberIds,
    ).toEqual([id]);
  }
});

describe("mirrored source assertions (pure)", () => {
  it("shared upstream record id marks redistributors mirrored and excludes them from independent count", () => {
    const upstream = "attack-pattern--shared-upstream";
    const annotated = annotateMirroredAssertions([
      {
        sourceId: "mitre",
        sourceName: "MITRE",
        sourceRecordId: upstream,
        sourceRecordNamespace: "mitre",
        originalSourceId: "mitre",
        retrievedAt: "2026-01-01T00:00:00.000Z",
        redistributable: true,
      },
      {
        sourceId: "taxii",
        sourceName: "TAXII",
        sourceRecordId: upstream,
        sourceRecordNamespace: "mitre",
        originalSourceId: "mitre",
        retrievedAt: "2026-01-01T00:00:00.000Z",
        redistributable: true,
      },
      {
        sourceId: "misp",
        sourceName: "MISP",
        sourceRecordId: upstream,
        sourceRecordNamespace: "mitre",
        originalSourceId: "mitre",
        retrievedAt: "2026-01-01T00:00:00.000Z",
        redistributable: true,
      },
    ]);
    expect(annotated.source_count).toBe(3);
    expect(annotated.mirror_count).toBe(2);
    expect(annotated.independent_corroboration_count).toBe(1);
    expect(annotated.assertions.filter((a) => a.mirrored)).toHaveLength(2);
    expect(annotated.assertions.filter((a) => !a.mirrored)).toHaveLength(1);
  });

  it("distinct MITRE id plus TAXII/MISP mirror pair: MITRE once, pair adds no extra independent", () => {
    // Pair shares an upstream; as a multi-member group it contributes one
    // primary only — mirrors never increment beyond that single credit.
    // MITRE's distinct id is a separate singleton group.
    const annotated = annotateMirroredAssertions([
      {
        sourceId: "mitre",
        sourceName: "MITRE",
        sourceRecordId: "mitre-native-1",
        retrievedAt: "2026-01-01T00:00:00.000Z",
        redistributable: true,
      },
      {
        sourceId: "taxii",
        sourceName: "TAXII",
        sourceRecordId: "shared-mirror-upstream",
        sourceRecordNamespace: "original",
        originalSourceId: "original",
        retrievedAt: "2026-01-01T00:00:00.000Z",
        redistributable: true,
      },
      {
        sourceId: "misp",
        sourceName: "MISP",
        sourceRecordId: "shared-mirror-upstream",
        sourceRecordNamespace: "original",
        originalSourceId: "original",
        retrievedAt: "2026-01-01T00:00:00.000Z",
        redistributable: true,
      },
    ]);
    expect(annotated.mirror_count).toBe(1);
    expect(annotated.independent_corroboration_count).toBe(2);
    expect(
      annotated.assertions.find((a) => a.sourceId === "mitre")?.mirrored,
    ).toBe(false);
  });
});

describe("canonical campaign via three sources (audit finding 6)", () => {
  it("three separately stored campaigns sharing upstream collapse at read-time to one canonical with mirrored assertions", async () => {
    // Audit case: same campaign LISTED SEPARATELY via MITRE, TAXII, MISP.
    // Distinct entity rows — no attachSource onto one id, no aliasEntity.
    const upstream = "campaign--operation-mirror";
    const mitre = campaign("camp-mitre", "mitre", "MITRE ATT&CK", upstream);
    const taxii = campaign("camp-taxii", "taxii", "TAXII Mirror", upstream);
    const misp = campaign("camp-misp", "misp", "MISP Mirror", upstream);
    await repo.putEntity(mitre);
    await repo.putEntity(taxii);
    await repo.putEntity(misp);

    // Stable canonical = lowest entity id among the identity group.
    const expectedCanonical = ["camp-misp", "camp-mitre", "camp-taxii"].sort(
      (a, b) => a.localeCompare(b),
    )[0]!;

    for (const id of ["camp-mitre", "camp-taxii", "camp-misp"] as const) {
      const view = await canonicalEntities(repo, principal.tenantId, id);
      expect(view).not.toBeNull();
      expect(view!.canonical_id).toBe(expectedCanonical);
      expect(view!.member_ids.sort()).toEqual(
        ["camp-misp", "camp-mitre", "camp-taxii"].sort(),
      );
      expect(view!.source_count).toBe(3);
      expect(view!.source_assertions).toHaveLength(3);
      expect(view!.mirror_count).toBe(2);
      expect(view!.independent_corroboration_count).toBe(1);
      expect(view!.source_assertions.filter((a) => a.mirrored)).toHaveLength(2);
      expect(new Set(view!.source_assertions.map((a) => a.sourceId))).toEqual(
        new Set(["mitre", "taxii", "misp"]),
      );
    }

    const listed = await browseCanonicalEntities(repo, principal.tenantId, {
      type: "campaign",
      limit: 50,
    });
    const rows = listed.data.filter((e) => e.name === "Operation Mirror");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.canonical_id).toBe(expectedCanonical);
    expect(rows[0]!.source_count).toBe(3);
    expect(rows[0]!.mirror_count).toBe(2);
    expect(rows[0]!.independent_corroboration_count).toBe(1);
  });
});

describe("latest assessment per observable + reversible alias", () => {
  it("one CVE assessed twice → one latest slot with assessment_count and expandable history", async () => {
    const obsId = "obs-cve-2024-canon";
    const now = "2026-06-01T00:00:00.000Z";
    const later = "2026-06-02T00:00:00.000Z";
    await repo.putObservable(
      {
        id: obsId,
        type: "cve",
        value: "CVE-2024-CANON",
        normalizedValue: "cve-2024-canon",
        createdAt: now,
        updatedAt: now,
      },
      {
        sourceId: "mitre",
        sourceName: "MITRE ATT&CK",
        retrievedAt: now,
        redistributable: true,
      },
      principal.tenantId,
    );
    const first = modelAssessment("assess-cve-1", obsId, now, {
      confidence: 0.4,
      analyst_decision: {
        field: "malicious",
        value: "suspicious",
        reason: "Initial triage — needs corroboration",
        analystId: principal.userId,
        createdAt: now,
      },
    });
    const second = modelAssessment("assess-cve-2", obsId, later, {
      confidence: 0.85,
      malicious: { probability: 0.9, classification: "malicious" },
      analyst_decision: {
        field: "malicious",
        value: "malicious",
        reason: "Revised after KEV listing confirmed",
        analystId: principal.userId,
        createdAt: later,
      },
    });
    await repo.saveAssessment(principal.tenantId, first, []);
    await repo.saveAssessment(principal.tenantId, second, []);

    const page = await latestAssessmentPerObservable(repo, principal.tenantId, {
      includeHistory: true,
    });
    const cveSlots = page.data.filter((s) => s.observable.id === obsId);
    expect(cveSlots).toHaveLength(1);
    expect(cveSlots[0]!.assessment_id).toBe("assess-cve-2");
    expect(cveSlots[0]!.assessment_count).toBe(2);
    expect(cveSlots[0]!.history).toHaveLength(2);
    expect(cveSlots[0]!.history!.map((h) => h.assessment_id)).toEqual([
      "assess-cve-2",
      "assess-cve-1",
    ]);
    expect(cveSlots[0]!.history![1]!.analyst_decision?.reason).toContain(
      "Initial triage",
    );
    // Older assessment still queryable directly — history not deleted.
    expect(
      await repo.assessment(principal.tenantId, "assess-cve-1"),
    ).not.toBeNull();
  });

  it("latestAssessmentPerObservable honors status filters on the deduped set", async () => {
    const now = "2026-07-01T00:00:00.000Z";
    const later = "2026-07-02T00:00:00.000Z";
    await repo.putObservable(
      {
        id: "obs-filter-a",
        type: "domain",
        value: "filter-a.test",
        normalizedValue: "filter-a.test",
        createdAt: now,
        updatedAt: now,
      },
      {
        sourceId: "mitre",
        sourceName: "MITRE ATT&CK",
        retrievedAt: now,
        redistributable: true,
      },
      principal.tenantId,
    );
    await repo.putObservable(
      {
        id: "obs-filter-b",
        type: "domain",
        value: "filter-b.test",
        normalizedValue: "filter-b.test",
        createdAt: now,
        updatedAt: now,
      },
      {
        sourceId: "mitre",
        sourceName: "MITRE ATT&CK",
        retrievedAt: now,
        redistributable: true,
      },
      principal.tenantId,
    );
    // Two assessments of A — latest confirmed; older pending ignored for slot.
    await repo.saveAssessment(
      principal.tenantId,
      modelAssessment("filter-a-1", "obs-filter-a", now, {
        status: "pending",
        observable: {
          id: "obs-filter-a",
          type: "domain",
          value: "filter-a.test",
          normalizedValue: "filter-a.test",
          createdAt: now,
          updatedAt: now,
        },
      }),
      [],
    );
    await repo.saveAssessment(
      principal.tenantId,
      modelAssessment("filter-a-2", "obs-filter-a", later, {
        status: "confirmed",
        observable: {
          id: "obs-filter-a",
          type: "domain",
          value: "filter-a.test",
          normalizedValue: "filter-a.test",
          createdAt: later,
          updatedAt: later,
        },
      }),
      [],
    );
    await repo.saveAssessment(
      principal.tenantId,
      modelAssessment("filter-b-1", "obs-filter-b", later, {
        status: "pending",
        observable: {
          id: "obs-filter-b",
          type: "domain",
          value: "filter-b.test",
          normalizedValue: "filter-b.test",
          createdAt: later,
          updatedAt: later,
        },
      }),
      [],
    );

    const pending = await latestAssessmentPerObservable(
      repo,
      principal.tenantId,
      { filters: { status: "pending" } },
    );
    const pendingIds = pending.data.map((s) => s.observable.id);
    expect(pendingIds).toContain("obs-filter-b");
    expect(pendingIds).not.toContain("obs-filter-a");

    const confirmed = await latestAssessmentPerObservable(
      repo,
      principal.tenantId,
      { filters: { status: "confirmed" } },
    );
    const confirmedIds = confirmed.data.map((s) => s.observable.id);
    expect(confirmedIds).toContain("obs-filter-a");
    expect(confirmedIds).not.toContain("obs-filter-b");
    expect(
      confirmed.data.find((s) => s.observable.id === "obs-filter-a")!
        .assessment_count,
    ).toBe(2);
  });

  it("alias resolution is reversible: un-alias restores separate views", async () => {
    const now = new Date().toISOString();
    const a: IntelEntity = {
      id: "actor-canonical",
      type: "threat-actor",
      name: "APT Canonical",
      description: "",
      aliases: [],
      data: {},
      provenance: {
        sourceId: "mitre",
        sourceName: "MITRE ATT&CK",
        sourceRecordId: "intrusion-set--canon",
        retrievedAt: now,
        redistributable: true,
      },
    };
    const b: IntelEntity = {
      id: "actor-alias",
      type: "threat-actor",
      name: "APT Alias Name",
      description: "",
      aliases: ["Alias Group"],
      data: {},
      provenance: {
        sourceId: "taxii",
        sourceName: "TAXII Mirror",
        sourceRecordId: "intrusion-set--alias",
        retrievedAt: now,
        redistributable: true,
      },
    };
    await repo.putEntity(a);
    await repo.putEntity(b);

    const before = await browseCanonicalEntities(repo, principal.tenantId, {
      type: "threat-actor",
      limit: 50,
    });
    const beforeIds = new Set(before.data.map((e) => e.id));
    expect(beforeIds.has("actor-canonical")).toBe(true);
    expect(beforeIds.has("actor-alias")).toBe(true);

    await aliasEntity(
      db,
      principal.tenantId,
      "actor-canonical",
      "actor-alias",
      "same-actor-name-match",
    );

    const aliased = await canonicalEntities(
      repo,
      principal.tenantId,
      "actor-alias",
    );
    expect(aliased!.canonical_id).toBe("actor-canonical");
    expect(aliased!.alias_ids).toContain("actor-alias");
    // Assertions from both entity rows surface under the canonical.
    expect(aliased!.source_count).toBeGreaterThanOrEqual(2);

    const during = await browseCanonicalEntities(repo, principal.tenantId, {
      type: "threat-actor",
      limit: 50,
    });
    const duringIds = new Set(during.data.map((e) => e.id));
    expect(duringIds.has("actor-canonical")).toBe(true);
    expect(duringIds.has("actor-alias")).toBe(false);

    const removed = await unaliasEntity(db, principal.tenantId, "actor-alias");
    expect(removed).toBe(true);

    const after = await browseCanonicalEntities(repo, principal.tenantId, {
      type: "threat-actor",
      limit: 50,
    });
    const afterIds = new Set(after.data.map((e) => e.id));
    expect(afterIds.has("actor-canonical")).toBe(true);
    expect(afterIds.has("actor-alias")).toBe(true);
    const resolved = await canonicalEntities(
      repo,
      principal.tenantId,
      "actor-alias",
    );
    expect(resolved!.canonical_id).toBe("actor-alias");
  });
});

describe("tenant visibility: private peers must not leak", () => {
  it("tenant A does not see tenant B private campaign sharing the same externalId", async () => {
    const now = new Date().toISOString();
    await db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind("tenant-a-vis", "Tenant A", now)
      .run();
    await db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind("tenant-b-vis", "Tenant B", now)
      .run();
    await db
      .prepare(
        "INSERT OR IGNORE INTO sources(id,name,independent_group,reliability,license) VALUES(?,?,?,?,?)",
      )
      .bind("upload", "Customer Upload", "customer", 0.5, "private")
      .run();

    const sharedExternal = "campaign--shared-public";
    const publicCamp: IntelEntity = {
      id: "camp-public-shared",
      type: "campaign",
      name: "Shared Public Campaign",
      description: "Visible to all",
      aliases: [],
      externalId: sharedExternal,
      data: {},
      provenance: {
        sourceId: "mitre",
        sourceName: "MITRE ATT&CK",
        sourceRecordId: sharedExternal,
        sourceRecordNamespace: "shared-campaign-origin",
        retrievedAt: now,
        redistributable: true,
      },
    };
    const privateCamp: IntelEntity = {
      id: "camp-private-b",
      type: "campaign",
      name: "Tenant B Private Campaign",
      description: "Secret",
      aliases: [],
      externalId: sharedExternal,
      data: {},
      provenance: {
        sourceId: "upload",
        sourceName: "Tenant B Secret Feed",
        sourceRecordId: sharedExternal + "-b",
        sourceRecordNamespace: "shared-campaign-origin",
        retrievedAt: now,
        redistributable: false,
      },
    };
    await repo.putEntity(publicCamp);
    await repo.putEntity(privateCamp);
    // tenant_observables FK → observables(id); stub so B can see the private entity.
    await db
      .prepare(
        "INSERT OR IGNORE INTO observables(id,type,normalized_value,data) VALUES(?,?,?,?)",
      )
      .bind(
        privateCamp.id,
        "domain",
        "tenant-b-private.campaign",
        JSON.stringify({ id: privateCamp.id }),
      )
      .run();
    await db
      .prepare(
        "INSERT OR IGNORE INTO tenant_observables(tenant_id,observable_id,created_at) VALUES(?,?,?)",
      )
      .bind("tenant-b-vis", privateCamp.id, now)
      .run();

    expect(await repo.visible("tenant-a-vis", publicCamp.id)).toBe(true);
    expect(await repo.visible("tenant-a-vis", privateCamp.id)).toBe(false);
    expect(await repo.visible("tenant-b-vis", privateCamp.id)).toBe(true);

    const forA = await canonicalEntities(repo, "tenant-a-vis", publicCamp.id);
    expect(forA).not.toBeNull();
    expect(forA!.member_ids).not.toContain(privateCamp.id);
    expect(forA!.canonical_id).not.toBe(privateCamp.id);
    expect(
      forA!.source_assertions.some(
        (s) => s.sourceName === "Tenant B Secret Feed",
      ),
    ).toBe(false);
    expect(JSON.stringify(forA)).not.toContain("Tenant B Secret Feed");
    expect(JSON.stringify(forA)).not.toContain(privateCamp.id);

    const browseA = await browseCanonicalEntities(repo, "tenant-a-vis", {
      type: "campaign",
      limit: 50,
    });
    const aRow = browseA.data.find((e) => e.externalId === sharedExternal);
    expect(aRow).toBeTruthy();
    expect(JSON.stringify(aRow)).not.toContain("Tenant B Secret Feed");
    expect(JSON.stringify(aRow)).not.toContain(privateCamp.id);
    expect(aRow!.canonical_id).not.toBe(privateCamp.id);

    const forB = await canonicalEntities(repo, "tenant-b-vis", publicCamp.id);
    expect(forB).not.toBeNull();
    expect(forB!.member_ids).toContain(publicCamp.id);
    expect(forB!.member_ids).toContain(privateCamp.id);
    expect(
      forB!.source_assertions.some(
        (s) => s.sourceName === "Tenant B Secret Feed",
      ),
    ).toBe(true);

    expect(
      await canonicalEntities(repo, "tenant-a-vis", privateCamp.id),
    ).toBeNull();
  });
});

it("equal IDs and external IDs from unrelated providers do not merge campaigns", async () => {
  const a = campaign("provider-a-campaign", "mitre", "Provider A", "42");
  const b = campaign("provider-b-campaign", "taxii", "Provider B", "42");
  a.externalId = b.externalId = "provider-local-42";
  delete a.provenance.sourceRecordNamespace;
  delete b.provenance.sourceRecordNamespace;
  delete a.provenance.originalSourceId;
  delete b.provenance.originalSourceId;
  await repo.putEntity(a);
  await repo.putEntity(b);
  expect(
    (await identityGroup(repo, principal.tenantId, a.id))?.memberIds,
  ).toEqual([a.id]);
  expect(
    (await identityGroup(repo, principal.tenantId, b.id))?.memberIds,
  ).toEqual([b.id]);
});

it("excluded source policies remove corroboration assertions from canonical views", async () => {
  const a = campaign("policy-campaign", "mitre", "Provider A", "policy-id");
  await repo.putEntity(a);
  await repo.attachSource(a.id, {
    ...a,
    provenance: {
      ...a.provenance,
      sourceId: "taxii",
      sourceName: "Provider B",
      sourceRecordId: "other-policy-id",
      originalSourceId: "other-origin",
      sourceRecordNamespace: "other-origin",
    },
  });
  const before = await canonicalEntities(repo, principal.tenantId, a.id);
  expect(before!.source_assertions.map((p) => p.sourceId)).toContain("taxii");
  await db
    .prepare(
      "INSERT INTO tenant_source_policy(tenant_id,source_id,enabled,reason,updated_at) VALUES(?,?,0,'test exclusion','2026-10-16T00:00:00.000Z') ON CONFLICT(tenant_id,source_id) DO UPDATE SET enabled=0",
    )
    .bind(principal.tenantId, "taxii")
    .run();
  const after = await canonicalEntities(repo, principal.tenantId, a.id);
  expect(after!.source_assertions.map((p) => p.sourceId)).not.toContain(
    "taxii",
  );
  expect(after!.independent_corroboration_count).toBe(1);
});
