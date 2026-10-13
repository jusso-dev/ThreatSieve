import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { z } from "zod";
import { exportStix, type StixBundle } from "../packages/stix/src/index";
import {
  publicationState,
  publishableClaims,
  type PublicationState,
} from "../packages/stix/src/policy";
import type { Assessment, Evidence } from "../packages/schemas/src/index";
import { migrationStatements } from "../packages/database/src/migrations";
import { Repository } from "../packages/database/src/repository";
import { digest } from "../packages/intel/src/normalise";
import { app } from "../apps/api/src/index";

const DAY = 86400000;
const daysAgo = (n: number) => new Date(Date.now() - n * DAY).toISOString();

function evidence(
  id: string,
  sourceId: string,
  redistributable: boolean,
  data: Record<string, unknown>,
  observedAt: string,
): Evidence {
  return {
    id,
    type: "feed",
    sourceId,
    provenance: {
      sourceId,
      sourceName: sourceId + " feed",
      retrievedAt: daysAgo(70),
      redistributable,
    },
    data,
    confidence: 0.9,
    createdAt: daysAgo(70),
    observedAt,
    behavioural: false,
  };
}

/**
 * Reference failure case (downloaded export for IP 162.243.103.246): pending
 * review, stale evidence, 41% confidence, restricted source evidence stripped
 * while the derived malicious classification and C2 role remained.
 */
function auditCase(): Assessment {
  const created = daysAgo(70);
  return {
    schema_version: "1.0",
    assessment_id: "assess-a41f5946-1947-4b12-8eb2-0ed467bcba67",
    observable: {
      id: "obs-162-243-103-246",
      type: "ipv4",
      value: "162.243.103.246",
      normalizedValue: "162.243.103.246",
      createdAt: created,
      updatedAt: created,
    },
    malicious: { probability: 0.41, classification: "malicious" },
    role: { value: "c2", probability: 0.8 },
    severity: "high",
    confidence: 0.41,
    confidence_factors: [],
    attack: [
      {
        techniqueId: "T1071.001",
        entityId: "attack-entity",
        probability: 0.7,
        confidence: 0.7,
        evidenceIds: ["ev-restricted"],
        mappingType: "model_inferred",
        status: "probable",
      },
    ],
    actors: [
      {
        id: "actor-secret",
        name: "Synthetic Actor",
        association_probability: 0.5,
        evidenceIds: ["ev-restricted"],
        assertion_type: "model_inferred",
        dimensions: ["malware_overlap"],
        strongAttribution: false,
      },
    ],
    malware: [{ id: "malware-secret", name: "TestRAT", confidence: 0.9 }],
    customer: {
      relevance: 0.5,
      priority: "medium",
      reasons: [],
      exposedAssets: 0,
      observed: false,
    },
    recommended_actions: [
      { action: "block", confidence: 0.9, reason_codes: [] },
    ],
    human_review: true,
    human_review_probability: 0.8,
    evidence: [
      evidence(
        "ev-restricted",
        "threatfox-restricted",
        false,
        { malicious: true, role: "c2", malwareEntityId: "malware-secret" },
        daysAgo(20),
      ),
      evidence("ev-permitted", "otx", true, { seen: true }, daysAgo(60)),
    ],
    sources: [
      {
        sourceId: "threatfox-restricted",
        sourceName: "ThreatFox licensed feed",
        retrievedAt: created,
        redistributable: false,
      },
      {
        sourceId: "otx",
        sourceName: "AlienVault OTX",
        retrievedAt: created,
        redistributable: true,
      },
    ],
    reason_codes: ["KNOWN_C2"],
    models: {
      classifier: "clef-flash",
      schema_version: "1.0",
      question_set_version: "q1",
    },
    runs: [],
    evidence_version: "v1",
    created_at: created,
    status: "pending",
    demo: false,
  };
}

/** Audit case with the review, freshness and confidence gates cleared. */
function cleared(): Assessment {
  return {
    ...auditCase(),
    status: "confirmed",
    human_review: false,
    confidence: 0.9,
    evidence: [
      evidence(
        "ev-restricted",
        "threatfox-restricted",
        false,
        { malicious: true, role: "c2", malwareEntityId: "malware-secret" },
        daysAgo(2),
      ),
      evidence(
        "ev-permitted",
        "otx",
        true,
        { malicious: true, malwareEntityId: "malware-public" },
        daysAgo(2),
      ),
    ],
  };
}

const indicatorOf = (bundle: StixBundle) =>
  bundle.objects.find((o) => o.type === "indicator")!;
const noteOf = (bundle: StixBundle) =>
  JSON.parse(
    String(bundle.objects.find((o) => o.type === "note")!.content),
  ) as Record<string, unknown>;

describe("publication policy — pinned shape", () => {
  it("exposes the pinned PublicationState shape with machine-readable reasons", () => {
    const state = publicationState(auditCase());
    expect(state).toMatchObject({
      audience: "operational",
      eligible: false,
      revoked: false,
    });
    expect(typeof state.valid_until).toBe("string");
    expect(typeof state.last_observed).toBe("string");
    expect(["active", "stale", "expired", "unknown"]).toContain(state.activity);
    expect(state.reasons.length).toBeGreaterThan(0);
    for (const reason of state.reasons)
      expect(reason).toMatch(/^[A-Z][A-Z0-9_]*$/);
  });
});

describe("publication policy — audit regression", () => {
  it("marks the operational export non-actionable and drops restricted-derived claims", () => {
    const a = auditCase();
    const state = publicationState(a);
    expect(state.eligible).toBe(false);
    expect(state.reasons).toContain("PENDING_REVIEW");
    expect(state.reasons).toContain("STALE_EVIDENCE");
    expect(state.reasons).toContain("LOW_CONFIDENCE");
    expect(state.activity).toBe("stale");
    expect(state.revoked).toBe(false);
    expect(state.last_observed).not.toBeNull();
    expect(state.valid_until).toBe(
      new Date(Date.parse(state.last_observed!) + 90 * DAY).toISOString(),
    );

    const bundle = exportStix(a, { audience: "operational" });
    const indicator = indicatorOf(bundle);
    expect(indicator.indicator_types).not.toEqual(["malicious-activity"]);
    expect(indicator.indicator_types).toEqual(["anomalous-activity"]);
    expect(indicator.x_threatsieve_approved_for_operational_use).toBe(false);
    const published = indicator.x_threatsieve_publication_state as
      PublicationState;
    expect(published).toBeDefined();
    expect(published.eligible).toBe(false);
    expect(published.reasons).toEqual(state.reasons);
    expect(published.audience).toBe("operational");
    expect(indicator.valid_until).toBe(state.valid_until);
    expect(indicator.revoked).toBe(false);

    // Derived-data rights: the malicious classification, C2 role, malware,
    // attack and actor claims were derived only from restricted evidence and
    // must be dropped entirely — not merely hidden.
    expect(indicator.x_threatsieve_classification).toBeUndefined();
    expect(indicator.x_threatsieve_model_classification).toBeUndefined();
    expect(bundle.objects.some((o) => o.type === "malware")).toBe(false);
    expect(bundle.objects.some((o) => o.type === "attack-pattern")).toBe(false);
    expect(bundle.objects.some((o) => o.type === "relationship")).toBe(false);
    const note = noteOf(bundle);
    expect(note.classification).toBeUndefined();
    expect(note.role).toBeUndefined();
    expect(note.actor_associations).toEqual([]);
    const serialized = JSON.stringify(bundle);
    expect(serialized).not.toContain('"c2"');
    expect(serialized).not.toContain("TestRAT");
    expect(serialized).not.toContain("actor-secret");
  });

  it("keeps model history and the review flag in the research export", () => {
    const a = auditCase();
    const bundle = exportStix(a, { audience: "research" });
    const indicator = indicatorOf(bundle);
    const note = noteOf(bundle);
    expect(indicator.x_threatsieve_model_classification).toEqual(a.malicious);
    expect(note.model).toEqual(a.models);
    expect(note.review).toBe(true);
    // Research keeps today's full behavior, plus the publication state block.
    expect(indicator.x_threatsieve_classification).toBeDefined();
    expect(note.role).toEqual(a.role);
    const published = indicator.x_threatsieve_publication_state as
      PublicationState;
    expect(published).toBeDefined();
    expect(published.eligible).toBe(false);
    expect(published.audience).toBe("research");
  });
});

describe("publication policy — operational eligibility", () => {
  it("requires review clearance, redistributable evidence, freshness and confidence together", () => {
    const eligible = publicationState(cleared());
    expect(eligible.eligible).toBe(true);
    expect(eligible.reasons).toEqual([]);
    expect(eligible.activity).toBe("active");

    expect(
      publicationState({ ...cleared(), status: "pending" }).reasons,
    ).toContain("PENDING_REVIEW");
    expect(
      publicationState({ ...cleared(), human_review: true }).reasons,
    ).toContain("PENDING_REVIEW");

    const restrictedOnly = {
      ...cleared(),
      evidence: cleared().evidence.filter((e) => !e.provenance.redistributable),
    };
    const noRedistributable = publicationState(restrictedOnly);
    expect(noRedistributable.eligible).toBe(false);
    expect(noRedistributable.reasons).toContain(
      "NO_REDISTRIBUTABLE_EVIDENCE",
    );
    expect(noRedistributable.last_observed).toBeNull();
    expect(noRedistributable.valid_until).toBeNull();
    expect(noRedistributable.activity).toBe("unknown");

    const stale = publicationState({
      ...cleared(),
      evidence: [
        evidence("ev-permitted", "otx", true, { malicious: true }, daysAgo(60)),
      ],
    });
    expect(stale.eligible).toBe(false);
    expect(stale.reasons).toContain("STALE_EVIDENCE");
    expect(stale.activity).toBe("stale");

    const expired = publicationState({
      ...cleared(),
      evidence: [
        evidence("ev-permitted", "otx", true, { malicious: true }, daysAgo(100)),
      ],
    });
    expect(expired.eligible).toBe(false);
    expect(expired.reasons).toContain("EXPIRED");
    expect(expired.activity).toBe("expired");
    expect(Date.parse(expired.valid_until!)).toBeLessThan(Date.now());

    const lowConfidence = publicationState({ ...cleared(), confidence: 0.41 });
    expect(lowConfidence.eligible).toBe(false);
    expect(lowConfidence.reasons).toContain("LOW_CONFIDENCE");
  });

  it("lets an eligible operational export claim malicious-activity only with permitted support", () => {
    const a = cleared();
    const bundle = exportStix(a, { audience: "operational" });
    const indicator = indicatorOf(bundle);
    expect(indicator.indicator_types).toEqual(["malicious-activity"]);
    expect(indicator.x_threatsieve_approved_for_operational_use).toBe(true);
    expect(indicator.valid_until).toBe(publicationState(a).valid_until);
    expect(indicator.revoked).toBe(false);
    // The C2 role claim still rests on restricted evidence alone and is gone.
    expect(noteOf(bundle).role).toBeUndefined();
  });
});

describe("publication policy — derived-data rights", () => {
  function mixedSupport(): Assessment {
    return {
      ...cleared(),
      role: { value: "phishing", probability: 0.8 },
      attack: [
        {
          techniqueId: "T1071.001",
          entityId: "attack-entity",
          probability: 0.7,
          confidence: 0.7,
          evidenceIds: ["ev-restricted"],
          mappingType: "model_inferred",
          status: "probable",
        },
        {
          techniqueId: "T1566",
          entityId: "attack-entity-2",
          probability: 0.7,
          confidence: 0.7,
          evidenceIds: ["ev-permitted"],
          mappingType: "model_inferred",
          status: "probable",
        },
      ],
      actors: [
        {
          id: "actor-secret",
          name: "Synthetic Actor",
          association_probability: 0.5,
          evidenceIds: ["ev-restricted"],
          assertion_type: "model_inferred",
          dimensions: ["malware_overlap"],
          strongAttribution: false,
        },
        {
          id: "actor-public",
          name: "Public Actor",
          association_probability: 0.5,
          evidenceIds: ["ev-permitted"],
          assertion_type: "model_inferred",
          dimensions: ["malware_overlap"],
          strongAttribution: false,
        },
      ],
      malware: [
        { id: "malware-secret", name: "TestRAT", confidence: 0.9 },
        { id: "malware-public", name: "PublicRAT", confidence: 0.9 },
      ],
      evidence: [
        evidence(
          "ev-restricted",
          "threatfox-restricted",
          false,
          { malicious: true, role: "c2", malwareEntityId: "malware-secret" },
          daysAgo(2),
        ),
        evidence(
          "ev-permitted",
          "otx",
          true,
          {
            malicious: true,
            role: "phishing",
            malwareEntityId: "malware-public",
          },
          daysAgo(2),
        ),
      ],
    };
  }

  it("drops restricted-backed claims and keeps permitted-backed claims in operational exports", () => {
    const bundle = exportStix(mixedSupport(), { audience: "operational" });
    const serialized = JSON.stringify(bundle);
    expect(serialized).toContain("T1566");
    expect(serialized).not.toContain("T1071.001");
    expect(serialized).toContain("PublicRAT");
    expect(serialized).not.toContain("TestRAT");
    expect(serialized).toContain("actor-public");
    expect(serialized).not.toContain("actor-secret");
    expect(noteOf(bundle).role).toEqual({
      value: "phishing",
      probability: 0.8,
    });
  });

  it("derived-data rights trump includeRestricted in operational exports", () => {
    const bundle = exportStix(mixedSupport(), {
      includeRestricted: true,
      audience: "operational",
    });
    const serialized = JSON.stringify(bundle);
    expect(serialized).not.toContain("T1071.001");
    expect(serialized).not.toContain("TestRAT");
    expect(serialized).not.toContain("actor-secret");
  });

  it("research exports keep today's behavior including restricted-backed claims", () => {
    const bundle = exportStix(mixedSupport(), {
      includeRestricted: true,
      audience: "research",
    });
    const serialized = JSON.stringify(bundle);
    expect(serialized).toContain("T1071.001");
    expect(serialized).toContain("TestRAT");
  });

  it("publishableClaims is the single rights decision used for operational claims", () => {
    const rights = publishableClaims(mixedSupport());
    expect(rights.classification).toBe(true);
    expect(rights.role).toBe(true);
    expect(rights.attack.get("T1071.001")).toBeUndefined();
    expect(rights.attack.get("T1566")).toEqual(["ev-permitted"]);
    expect(rights.malware.get("malware-secret")).toBeUndefined();
    expect(rights.malware.get("malware-public")).toEqual(["ev-permitted"]);
    expect(rights.actors.get("actor-secret")).toBeUndefined();
    expect(rights.actors.get("actor-public")).toEqual(["ev-permitted"]);
  });
});

describe("publication policy — revocation", () => {
  it("analyst benign override is authoritative: revoked, claims dropped", () => {
    const a: Assessment = {
      ...cleared(),
      effective_classification: "benign",
      analyst_decision: {
        field: "malicious",
        value: "benign",
        reason: "Confirmed legitimate infrastructure",
        analystId: "analyst-a",
        createdAt: daysAgo(1),
      },
      role: { value: "c2", probability: 0.8 },
    };
    const state = publicationState(a);
    expect(state.revoked).toBe(true);
    expect(state.eligible).toBe(false);
    expect(state.reasons).toContain("REVOKED");

    const bundle = exportStix(a, { audience: "operational" });
    const indicator = indicatorOf(bundle);
    expect(indicator.revoked).toBe(true);
    expect(indicator.indicator_types).toEqual(["benign"]);
    expect(indicator.x_threatsieve_approved_for_operational_use).toBe(false);
    // Malicious claims are dropped even though permitted evidence supports them.
    expect(bundle.objects.some((o) => o.type === "malware")).toBe(false);
    expect(bundle.objects.some((o) => o.type === "attack-pattern")).toBe(false);
    expect(noteOf(bundle).role).toBeUndefined();
    expect(noteOf(bundle).actor_associations).toEqual([]);

    // Research keeps the historical record including the model output.
    const research = exportStix(a, { audience: "research" });
    expect(indicatorOf(research).x_threatsieve_model_classification).toEqual(
      a.malicious,
    );
  });
});

describe("GET /v1/assessments/:id/stix audience separation", () => {
  let mf: Miniflare;
  let db: D1Database;
  const headers = { Authorization: "Bearer publication-policy-test-key" };
  const nonEligible = auditCase();
  const eligible = {
    ...cleared(),
    assessment_id: "assess-operational-eligible",
    observable: {
      ...cleared().observable,
      id: "obs-eligible",
      value: "198.51.100.99",
      normalizedValue: "198.51.100.99",
    },
  };
  beforeAll(async () => {
    mf = new Miniflare({
      modules: true,
      script: 'export default {fetch(){return new Response("ok")}}',
      compatibilityDate: "2026-08-06",
      d1Databases: ["DB"],
    });
    db = await mf.getD1Database("DB");
    for (const name of readdirSync("migrations").sort()) {
      const sql = readFileSync("migrations/" + name, "utf8");
      for (const statement of migrationStatements(sql))
        await db.prepare(statement).run();
    }
    await db
      .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
      .bind("tenant-a", "A", new Date().toISOString())
      .run();
    await db
      .prepare(
        "INSERT INTO api_keys(id,tenant_id,user_id,name,hash,scopes,created_at) VALUES(?,?,?,?,?,?,?)",
      )
      .bind(
        "key-a",
        "tenant-a",
        "analyst-a",
        "Test",
        await digest("publication-policy-test-key"),
        JSON.stringify(["admin"]),
        new Date().toISOString(),
      )
      .run();
    const repo = new Repository(db);
    for (const a of [nonEligible, eligible]) {
      await db
        .prepare(
          "INSERT INTO entities(id,type,name,external_id,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        )
        .bind(
          a.observable.id,
          "observable",
          a.observable.normalizedValue,
          null,
          "{}",
          a.created_at,
          a.created_at,
        )
        .run();
      await db
        .prepare(
          "INSERT INTO observables(id,type,normalized_value,first_seen,last_seen,data) VALUES(?,?,?,?,?,?)",
        )
        .bind(
          a.observable.id,
          a.observable.type,
          a.observable.normalizedValue,
          null,
          null,
          "{}",
        )
        .run();
    }
    await repo.saveAssessment("tenant-a", nonEligible, []);
    await repo.saveAssessment("tenant-a", eligible, []);
  });
  afterAll(async () => {
    await mf?.dispose();
  });
  const env = () => ({ DB: db, WEB_ORIGIN: "https://web.test" });

  it("defaults to research and keeps full history", async () => {
    const response = await app.request(
      "/v1/assessments/" + nonEligible.assessment_id + "/stix",
      { headers },
      env(),
    );
    expect(response.status).toBe(200);
    const bundle = z
      .object({ objects: z.array(z.record(z.string(), z.unknown())) })
      .parse(await response.json());
    const indicator = bundle.objects.find((o) => o.type === "indicator")!;
    expect(indicator.x_threatsieve_model_classification).toBeDefined();
    expect(indicator.x_threatsieve_approved_for_operational_use).toBeUndefined();
    expect(indicator.x_threatsieve_publication_state).toBeDefined();
  });

  it("never returns an operational-actionable bundle for non-eligible assessments", async () => {
    const response = await app.request(
      "/v1/assessments/" +
        nonEligible.assessment_id +
        "/stix?audience=operational",
      { headers },
      env(),
    );
    // Still valid research material, so it exports — unambiguously non-actionable.
    expect(response.status).toBe(200);
    const bundle = z
      .object({ objects: z.array(z.record(z.string(), z.unknown())) })
      .parse(await response.json());
    const indicator = bundle.objects.find((o) => o.type === "indicator")!;
    expect(indicator.indicator_types).not.toEqual(["malicious-activity"]);
    expect(indicator.x_threatsieve_approved_for_operational_use).toBe(false);
    expect(indicator.x_threatsieve_publication_state).toBeDefined();
    expect(indicator.valid_until).toBeDefined();
    expect(indicator.revoked).toBe(false);
    expect(JSON.stringify(bundle)).not.toContain("TestRAT");
  });

  it("approves eligible assessments for operational use and rejects unknown audiences", async () => {
    const approved = await app.request(
      "/v1/assessments/" + eligible.assessment_id + "/stix?audience=operational",
      { headers },
      env(),
    );
    expect(approved.status).toBe(200);
    const bundle = z
      .object({ objects: z.array(z.record(z.string(), z.unknown())) })
      .parse(await approved.json());
    const indicator = bundle.objects.find((o) => o.type === "indicator")!;
    expect(indicator.indicator_types).toEqual(["malicious-activity"]);
    expect(indicator.x_threatsieve_approved_for_operational_use).toBe(true);
    const rejected = await app.request(
      "/v1/assessments/" +
        nonEligible.assessment_id +
        "/stix?audience=operational-maybe",
      { headers },
      env(),
    );
    expect(rejected.status).toBe(400);
  });
});
