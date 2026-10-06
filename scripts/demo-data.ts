import { hashPassword } from "better-auth/crypto";
import { normalise, digest } from "../packages/intel/src/normalise";
import {
  EnvironmentSchema,
  type Assessment,
  type Evidence,
  type IntelEntity,
  type IntelRelationship,
} from "../packages/schemas/src/index";

export async function buildDemoSeed() {
  const tenant = "demo-tenant";
  const analyst = "demo-analyst";
  const now = new Date().toISOString();
  const token =
    "ts_" +
    crypto.randomUUID().replaceAll("-", "") +
    crypto.randomUUID().replaceAll("-", "");
  const sql: string[] = [];
  let firstAssessment: Assessment | undefined;
  const q = (v: unknown) =>
    v === null || v === undefined
      ? "NULL"
      : typeof v === "number"
        ? String(v)
        : "'" + String(v).replaceAll("'", "''") + "'";
  const insert = (table: string, columns: string[], values: unknown[]) =>
    sql.push(
      `INSERT OR REPLACE INTO ${table}(${columns.join(",")}) VALUES(${values.map(q).join(",")});`,
    );
  insert(
    "tenants",
    ["id", "name", "created_at", "slug"],
    [tenant, "ThreatSieve demonstration", now, "demo"],
  );
  insert(
    "users",
    ["id", "email", "created_at", "name", "email_verified", "updated_at"],
    [analyst, "analyst@example.test", now, "Demo analyst", 1, now],
  );
  insert(
    "tenant_members",
    ["tenant_id", "user_id", "role", "id", "created_at"],
    [tenant, analyst, "admin", "demo-membership", now],
  );
  insert(
    "auth_accounts",
    [
      "id",
      "account_id",
      "provider_id",
      "user_id",
      "password",
      "created_at",
      "updated_at",
    ],
    [
      "demo-credential",
      analyst,
      "credential",
      analyst,
      await hashPassword("ThreatSieve local demo only!"),
      now,
      now,
    ],
  );
  insert(
    "api_keys",
    ["id", "tenant_id", "user_id", "name", "hash", "scopes", "created_at"],
    [
      "demo-local-key",
      tenant,
      analyst,
      "Local demonstration",
      await digest(token),
      JSON.stringify(["admin"]),
      now,
    ],
  );
  const environment = EnvironmentSchema.parse({
    technologies: ["FortiGate", "Microsoft 365", "Windows 11"],
    vendors: ["Fortinet"],
    products: ["FortiOS"],
    cloudProviders: ["AWS", "Cloudflare"],
    operatingSystems: ["Windows 11"],
    industries: ["Technology"],
    countries: ["Australia"],
  });
  insert(
    "customer_environments",
    ["tenant_id", "data", "updated_at"],
    [tenant, JSON.stringify(environment), now],
  );
  for (let i = 1; i <= 3; i++)
    insert(
      "customer_assets",
      ["id", "tenant_id", "name", "product", "internet_exposed", "data"],
      ["demo-edge-" + i, tenant, "Demo edge gateway " + i, "FortiOS", 1, "{}"],
    );
  const p = {
    sourceId: "demo",
    sourceName: "Synthetic demonstration",
    retrievedAt: now,
    license: "Synthetic test data only",
    redistributable: true,
  };
  const putEntity = (e: IntelEntity) => {
    insert(
      "entities",
      [
        "id",
        "type",
        "name",
        "external_id",
        "data",
        "created_at",
        "updated_at",
        "public_intel",
      ],
      [e.id, e.type, e.name, e.externalId, JSON.stringify(e), now, now, 1],
    );
    insert(
      "entity_sources",
      ["entity_id", "source_id", "source_record_id", "provenance"],
      [e.id, "demo", e.id, JSON.stringify(p)],
    );
    insert(
      "entity_aliases",
      ["alias", "entity_id", "source_id"],
      [e.name.toLowerCase(), e.id, "demo"],
    );
  };
  const malware: IntelEntity = {
    id: "malware--b1111111-1111-4111-8111-111111111111",
    type: "malware",
    name: "DemoRAT",
    description:
      "Synthetic malware entity used solely to demonstrate source-backed relationships. No real-world actor attribution.",
    aliases: ["Demo remote access tool"],
    data: { synthetic: true },
    provenance: p,
  };
  putEntity(malware);
  const technique: IntelEntity = {
    id: "attack-pattern--b2222222-2222-4222-8222-222222222222",
    type: "attack-technique",
    name: "Web Protocols (demonstration mapping)",
    externalId: "T1071.001",
    description:
      "This test scenario describes web-protocol command-and-control behaviour; the association is synthetic.",
    aliases: [],
    data: { synthetic: true },
    provenance: p,
  };
  putEntity(technique);
  const scenarios = [
    {
      value: "beacon.demo.example",
      title:
        "Synthetic feed reports command-and-control activity; test telemetry shows repeated HTTP POST beacons.",
      role: "c2" as const,
      p: 0.98,
      confidence: 0.93,
      relevance: 0.91,
      severity: "critical" as const,
      observed: true,
      behavioural: true,
      review: false,
    },
    {
      value: "192.0.2.45",
      title:
        "Conflicting synthetic evidence: one source reports C2; another reports legitimate hosted services.",
      role: "c2" as const,
      p: 0.68,
      confidence: 0.48,
      relevance: 0.54,
      severity: "high" as const,
      observed: false,
      behavioural: false,
      review: true,
    },
    {
      value: "a9".repeat(32),
      title: "Synthetic malware payload hash associated with DemoRAT.",
      role: "payload" as const,
      p: 0.99,
      confidence: 0.94,
      relevance: 0.74,
      severity: "high" as const,
      observed: true,
      behavioural: false,
      review: false,
    },
    {
      value: "CVE-2024-21762",
      title:
        "Demonstration of a KEV-style exposure finding for FortiOS. Inventory and affected assets are synthetic.",
      role: "exploit" as const,
      p: 0.5,
      confidence: 0.96,
      relevance: 0.97,
      severity: "critical" as const,
      observed: false,
      behavioural: false,
      review: true,
    },
    {
      value: "edge-07.demo.example",
      title:
        "Synthetic infrastructure linked by a common malware report. Actor attribution remains unknown.",
      role: "unknown" as const,
      p: 0.73,
      confidence: 0.66,
      relevance: 0.44,
      severity: "medium" as const,
      observed: false,
      behavioural: false,
      review: true,
    },
    {
      value: "198.51.100.10",
      title:
        "Synthetic shared-cloud address. A malicious hosted domain does not establish maliciousness of the shared IP.",
      role: "benign" as const,
      p: 0.04,
      confidence: 0.89,
      relevance: 0.08,
      severity: "informational" as const,
      observed: false,
      behavioural: false,
      review: false,
    },
  ];
  for (const [index, s] of scenarios.entries()) {
    const obs = await normalise(s.value);
    const created = new Date(Date.now() - index * 42 * 60000).toISOString();
    obs.firstSeen = new Date(Date.now() - 86400000).toISOString();
    obs.lastSeen = created;
    putEntity({
      id: obs.id,
      type: "observable",
      name: obs.normalizedValue,
      description: s.title,
      aliases: [],
      data: { synthetic: true },
      provenance: p,
    });
    insert(
      "observables",
      ["id", "type", "normalized_value", "first_seen", "last_seen", "data"],
      [
        obs.id,
        obs.type,
        obs.normalizedValue,
        obs.firstSeen,
        obs.lastSeen,
        JSON.stringify(obs),
      ],
    );
    insert(
      "tenant_observables",
      ["tenant_id", "observable_id", "created_at"],
      [tenant, obs.id, now],
    );
    const evidence: Evidence = {
      id: "demo-ev-" + index,
      observableId: obs.id,
      type: s.behavioural ? "telemetry" : "feed",
      sourceId: "demo",
      data: {
        description: s.title,
        synthetic: true,
        malicious: index === 5 ? false : index === 3 ? undefined : true,
        role: s.role,
        ...([0, 2, 4].includes(index)
          ? {
              malwareEntityId: malware.id,
              malware: "DemoRAT",
              reportId: "demo-report-2026-01",
            }
          : {}),
        ...(index === 3
          ? {
              kev: true,
              product: "FortiOS",
              vendor: "Fortinet",
              dueDate: "2024-02-16",
            }
          : {}),
        ...(index === 5 ? { sharedInfrastructure: true } : {}),
      },
      provenance: p,
      confidence: s.confidence,
      createdAt: created,
      observedAt: created,
      behavioural: s.behavioural,
    };
    const evidenceList = [evidence];
    if (index === 1)
      evidenceList.push({
        ...evidence,
        id: evidence.id + "-conflict",
        data: {
          description:
            "Synthetic legitimate hosting report conflicts with malicious classification.",
          malicious: false,
          sharedInfrastructure: true,
        },
        confidence: 0.85,
      });
    for (const e of evidenceList)
      insert(
        "evidence",
        ["id", "entity_id", "source_id", "data", "observed_at", "created_at"],
        [e.id, obs.id, "demo", JSON.stringify(e), created, created],
      );
    const relation: IntelRelationship = {
      id: "demo-rel-" + index,
      sourceEntityId: obs.id,
      targetEntityId: malware.id,
      relationshipType: "INDICATES",
      assertionType: "source_claimed",
      confidence: 0.9,
      sourceIds: ["demo"],
      provenance: p,
      createdAt: created,
      updatedAt: created,
    };
    if ([0, 2, 4].includes(index))
      insert(
        "relationships",
        [
          "id",
          "source_entity_id",
          "target_entity_id",
          "relationship_type",
          "assertion_type",
          "confidence",
          "source_id",
          "data",
          "created_at",
        ],
        [
          relation.id,
          obs.id,
          malware.id,
          "INDICATES",
          "source_claimed",
          0.9,
          "demo",
          JSON.stringify(relation),
          created,
        ],
      );
    const a: Assessment = {
      schema_version: "1.0",
      assessment_id: "demo-assess-" + index,
      observable: obs,
      malicious: {
        probability: s.p,
        classification:
          index === 5
            ? "benign"
            : s.p >= 0.9
              ? "malicious"
              : index === 3
                ? "unknown"
                : "suspicious",
      },
      role: { value: s.role, probability: s.role === "unknown" ? 0.58 : 0.91 },
      severity: s.severity,
      confidence: s.confidence,
      confidence_factors: [
        {
          code: "LOW_EVIDENCE",
          value: s.confidence,
          weight: 1,
          evidenceIds: evidenceList.map((e) => e.id),
        },
      ],
      attack: s.behavioural
        ? [
            {
              techniqueId: "T1071.001",
              entityId: technique.id,
              probability: 0.93,
              confidence: 0.91,
              evidenceIds: [evidence.id],
              mappingType: "model_inferred",
              status: "accepted",
            },
          ]
        : [],
      actors: [],
      malware: [0, 2, 4].includes(index)
        ? [{ id: malware.id, name: malware.name, confidence: 0.9 }]
        : [],
      customer: {
        relevance: s.relevance,
        priority: s.severity === "informational" ? "low" : s.severity,
        observed: s.observed,
        exposedAssets: index === 3 ? 3 : 0,
        reasons:
          index === 3
            ? ["CISA_KEV", "CUSTOMER_TECH_MATCH", "CUSTOMER_ASSET_EXPOSED"]
            : s.observed
              ? ["CUSTOMER_OBSERVED"]
              : [],
      },
      recommended_actions: [
        {
          action:
            index === 3
              ? "patch"
              : index === 5
                ? "monitor"
                : s.review
                  ? "investigate"
                  : "hunt",
          confidence: s.confidence,
          reason_codes: index === 3 ? ["CISA_KEV"] : ["LOW_EVIDENCE"],
        },
      ],
      human_review: s.review,
      human_review_probability: s.review ? 0.78 : 0.12,
      evidence: evidenceList,
      sources: [p],
      reason_codes:
        index === 3
          ? ["CISA_KEV", "CUSTOMER_TECH_MATCH"]
          : index === 5
            ? ["SHARED_INFRASTRUCTURE", "KNOWN_BENIGN_INFRASTRUCTURE"]
            : s.role === "c2"
              ? ["KNOWN_C2"]
              : ["LOW_EVIDENCE"],
      models: {
        classifier: "synthetic-demonstration",
        schema_version: "observable-v1",
        question_set_version: "demo-v1",
      },
      runs: [],
      evidence_version: await digest(JSON.stringify(evidenceList)),
      created_at: created,
      status: "pending",
      demo: true,
    };
    insert(
      "assessments",
      [
        "id",
        "tenant_id",
        "observable_id",
        "evidence_version",
        "status",
        "severity",
        "confidence",
        "human_review",
        "data",
        "created_at",
      ],
      [
        a.assessment_id,
        tenant,
        obs.id,
        a.evidence_version,
        a.status,
        a.severity,
        a.confidence,
        Number(a.human_review),
        JSON.stringify(a),
        created,
      ],
    );
    if (index === 0) firstAssessment = a;
  }
  const rel: IntelRelationship = {
    id: "demo-malware-technique",
    sourceEntityId: malware.id,
    targetEntityId: technique.id,
    relationshipType: "USES",
    assertionType: "source_claimed",
    confidence: 0.9,
    sourceIds: ["demo"],
    provenance: p,
    createdAt: now,
    updatedAt: now,
  };
  insert(
    "relationships",
    [
      "id",
      "source_entity_id",
      "target_entity_id",
      "relationship_type",
      "assertion_type",
      "confidence",
      "source_id",
      "data",
      "created_at",
    ],
    [
      rel.id,
      malware.id,
      technique.id,
      "USES",
      "source_claimed",
      0.9,
      "demo",
      JSON.stringify(rel),
      now,
    ],
  );
  const cluster: IntelEntity = {
    id: "demo-cluster-0042",
    type: "cluster",
    name: "Unknown Cluster TS-2026-0042",
    description: "Synthetic infrastructure cluster with no actor attribution.",
    aliases: [],
    data: { synthetic: true },
    provenance: p,
  };
  putEntity(cluster);
  insert(
    "threat_clusters",
    [
      "id",
      "name",
      "status",
      "first_seen",
      "last_seen",
      "confidence",
      "observable_count",
    ],
    [
      cluster.id,
      cluster.name,
      "emerging",
      new Date(Date.now() - 86400000).toISOString(),
      now,
      0.72,
      3,
    ],
  );
  for (const i of [0, 2, 4])
    insert(
      "cluster_members",
      ["cluster_id", "observable_id", "evidence_id"],
      [cluster.id, (await normalise(scenarios[i]!.value)).id, "demo-ev-" + i],
    );
  return {
    statements: sql,
    tenant,
    analyst,
    token,
    firstAssessment: firstAssessment!,
  };
}
