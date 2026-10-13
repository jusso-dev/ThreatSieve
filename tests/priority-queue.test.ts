import { migrationStatements } from "../packages/database/src/migrations";
import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { Repository } from "../packages/database/src/repository";
import {
  assessmentOrders,
  encodeAssessmentCursor,
  urgencySql,
} from "../packages/database/src/assessment-query";
import { effectiveRecommendations } from "../packages/database/src/decision-state";
import {
  operationalUrgency,
  URGENCY_UNKNOWN,
  URGENCY_FRESHNESS_ACTIVITY,
  URGENCY_REVIEW_STATE,
} from "../packages/enterprise/src/urgency";
import {
  freshness,
  STALE_AFTER_DAYS,
  EXPIRES_AFTER_DAYS,
} from "../packages/intel/src/freshness";
import type {
  Assessment,
  Evidence,
  Principal,
} from "../packages/schemas/src/index";

let mf: Miniflare;
let db: D1Database;
let repo: Repository;

const principal: Principal = {
  tenantId: "tenant-a",
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
});
afterAll(async () => {
  await mf?.dispose();
});

async function tenant(id: string): Promise<Principal> {
  await db
    .prepare("INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)")
    .bind(id, id, new Date().toISOString())
    .run();
  return { ...principal, tenantId: id };
}

async function save(p: Principal, a: Assessment) {
  await repo.putObservable(
    a.observable,
    {
      sourceId: "threatfox",
      sourceName: "ThreatFox",
      retrievedAt: a.created_at,
      redistributable: true,
    },
    p.tenantId,
  );
  await repo.saveAssessment(p.tenantId, a, []);
}

const DAY_MS = 86400000;
const iso = (ms: number) => new Date(ms).toISOString();
const daysAgo = (days: number) => iso(Date.now() - days * DAY_MS);

function evidenceRecord(
  id: string,
  observedAt: string | undefined,
  data: Record<string, unknown> = {},
): Evidence {
  return {
    id,
    type: "feed",
    sourceId: "threatfox",
    provenance: {
      sourceId: "threatfox",
      sourceName: "ThreatFox",
      retrievedAt: observedAt ?? daysAgo(1),
      redistributable: true,
    },
    data: { malicious: true, ...data },
    confidence: 0.9,
    createdAt: observedAt ?? daysAgo(1),
    observedAt,
    behavioural: true,
  };
}

function makeAssessment(
  id: string,
  overrides: Partial<Assessment> = {},
): Assessment {
  const now = new Date().toISOString();
  return {
    schema_version: "1.0",
    assessment_id: id,
    observable: {
      id: "obs-" + id,
      type: "domain",
      value: id + ".test",
      normalizedValue: id + ".test",
      createdAt: now,
      updatedAt: now,
    },
    malicious: { probability: 0, classification: "unknown" },
    role: { value: "unknown", probability: 1 },
    severity: "low",
    confidence: 0,
    confidence_factors: [],
    attack: [],
    actors: [],
    malware: [],
    customer: {
      relevance: 0,
      priority: "low",
      reasons: [],
      exposedAssets: 0,
      observed: false,
    },
    recommended_actions: [
      { action: "enrich", confidence: 0, reason_codes: [] },
    ],
    human_review: true,
    human_review_probability: 0.8,
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
    created_at: now,
    status: "pending",
    demo: true,
    ...overrides,
  };
}

/** The audit's synthetic case: a .invalid domain with ZERO evidence. */
const syntheticInvalid = makeAssessment("audit-synthetic-invalid", {
  observable: {
    id: "obs-audit-synthetic-invalid",
    type: "domain",
    value: "proof-of-nothing.invalid",
    normalizedValue: "proof-of-nothing.invalid",
    createdAt: daysAgo(1),
    updatedAt: daysAgo(1),
  },
  // The audited distortion: an unsupported 5% model probability rendered as
  // customer relevance that outranked real exploitation.
  malicious: { probability: 0.05, classification: "unknown" },
  severity: "high",
  confidence: 0,
  customer: {
    relevance: 0.05,
    priority: "low",
    reasons: [],
    exposedAssets: 0,
    observed: false,
  },
  human_review: true,
  evidence: [],
  created_at: daysAgo(0.5),
});

/** The audited outranked item: a KEV-listed vulnerability with fresh evidence. */
const kevVulnerability = makeAssessment("audit-kev-vulnerability", {
  observable: {
    id: "obs-audit-kev-vulnerability",
    type: "cve",
    value: "CVE-2026-4242",
    normalizedValue: "CVE-2026-4242",
    createdAt: daysAgo(2),
    updatedAt: daysAgo(2),
  },
  malicious: { probability: 0.9, classification: "malicious" },
  severity: "critical",
  confidence: 0.8,
  customer: {
    relevance: 0.01,
    priority: "high",
    reasons: [],
    exposedAssets: 3,
    observed: true,
  },
  human_review: false,
  evidence: [evidenceRecord("ev-audit-kev", daysAgo(1), { kev: true })],
  created_at: daysAgo(1),
});

/** Evidence-backed but relevance-inflated: the old ordering's favourite. */
const relevanceInflated = makeAssessment("audit-relevance-inflated", {
  observable: {
    id: "obs-audit-relevance-inflated",
    type: "domain",
    value: "relevance-inflated.test",
    normalizedValue: "relevance-inflated.test",
    createdAt: daysAgo(2),
    updatedAt: daysAgo(2),
  },
  malicious: { probability: 0.4, classification: "suspicious" },
  severity: "medium",
  confidence: 0.5,
  customer: {
    relevance: 0.9,
    priority: "medium",
    reasons: [],
    exposedAssets: 1,
    observed: false,
  },
  human_review: true,
  evidence: [evidenceRecord("ev-audit-inflated", daysAgo(1))],
  created_at: daysAgo(0.2),
});

describe("audit finding 5 — priority queue decomposition", () => {
  it("a zero-evidence synthetic .invalid never outranks a KEV vulnerability; it routes to the enrichment backlog", async () => {
    const p = await tenant("t-priority-audit");
    await save(p, syntheticInvalid);
    await save(p, kevVulnerability);
    await save(p, relevanceInflated);
    // The documented ctx path: callers pass `vulnerabilities.kev` (the row the
    // CISA KEV feed writes) as ctx.kev.
    await db
      .prepare(
        "INSERT INTO entities(id,type,name,external_id,data,created_at,updated_at,public_intel) VALUES(?,?,?,?,?,?,?,?)",
      )
      .bind(
        "ent-audit-kev",
        "vulnerability",
        "CVE-2026-4242",
        "CVE-2026-4242",
        "{}",
        daysAgo(2),
        daysAgo(2),
        1,
      )
      .run();
    await db
      .prepare(
        "INSERT INTO vulnerabilities(entity_id,cve,vendor,product,kev,due_date) VALUES(?,?,?,?,?,?)",
      )
      .bind("ent-audit-kev", "CVE-2026-4242", "vendor", "product", 1, null)
      .run();
    const kevRow = await db
      .prepare("SELECT kev FROM vulnerabilities WHERE cve=?")
      .bind("CVE-2026-4242")
      .first<{ kev: number }>();

    // The regression's shape: under the old ordering (customer relevance
    // DESC) the synthetic item came first.
    expect(syntheticInvalid.customer.relevance).toBeGreaterThan(
      kevVulnerability.customer.relevance,
    );
    // The urgency ordering disagrees with that distortion.
    expect(
      operationalUrgency(kevVulnerability, {
        kev: kevRow?.kev === 1,
      }).urgency,
    ).toBeGreaterThan(operationalUrgency(syntheticInvalid).urgency);

    const summary = await repo.assessmentSummary(p.tenantId);
    // Excluded from the priority queue entirely...
    expect(summary.priority.map((a) => a.assessment_id)).not.toContain(
      syntheticInvalid.assessment_id,
    );
    // ...and the KEV item outranks a relevance-inflated competitor that the
    // old customer-relevance ordering put first.
    expect(relevanceInflated.customer.relevance).toBeGreaterThan(
      kevVulnerability.customer.relevance,
    );
    expect(summary.priority.map((a) => a.assessment_id)).toEqual([
      kevVulnerability.assessment_id,
      relevanceInflated.assessment_id,
    ]);
    // ...and listed in the enrichment backlog instead.
    expect(summary.enrichment_backlog.map((a) => a.assessment_id)).toEqual([
      syntheticInvalid.assessment_id,
    ]);

    // The urgency-ranked listing (the actionable queue order) never ranks the
    // zero-evidence item either.
    const ranked = await repo.assessments(p.tenantId, 50, undefined, {
      view: "all",
      sort: "relevance",
    });
    expect(ranked.map((a) => a.assessment_id)).not.toContain(
      syntheticInvalid.assessment_id,
    );
    expect(ranked[0]?.assessment_id).toBe(kevVulnerability.assessment_id);

    // Nothing is hidden: the item remains visible in unranked listings, where
    // its values render as Unknown (enrichment, not deletion).
    const newest = await repo.assessments(p.tenantId, 50, undefined, {
      view: "all",
    });
    expect(newest.map((a) => a.assessment_id)).toContain(
      syntheticInvalid.assessment_id,
    );
  });

  it("insufficient evidence is UNKNOWN, never low threat, and recommends enrich", () => {
    const u = operationalUrgency(syntheticInvalid);
    // Unknown components are distinguishable and contribute the neutral
    // midpoint — a zero-evidence claim is not a low-scoring claim.
    expect(u.unknownComponents).toEqual(
      expect.arrayContaining([
        "evidenceConfidence",
        "freshness",
        "exploitation",
      ]),
    );
    expect(u.components.evidenceConfidence).toBe(URGENCY_UNKNOWN);
    expect(u.components.evidenceConfidence).toBeGreaterThan(0);
    expect(u.components.freshness).toBe(URGENCY_UNKNOWN);
    expect(u.components.exploitation).toBe(URGENCY_UNKNOWN);
    // The composite carries the unknowns at neutral, so it cannot read as
    // "low threat": a fully-known worst case scores lower.
    const worstKnown = operationalUrgency(
      makeAssessment("worst-known", {
        confidence: 0,
        human_review: true,
        evidence: [
          {
            ...evidenceRecord("ev-old", undefined),
            observedAt: daysAgo(200),
            data: { malicious: false },
          },
        ],
      }),
      { kev: false },
    );
    expect(u.urgency).toBeGreaterThanOrEqual(worstKnown.urgency);
    // The read model routes it to enrichment (leaf 1.2.1, read-only).
    expect(effectiveRecommendations(syntheticInvalid).map((x) => x.action)).toEqual(
      ["enrich"],
    );
  });

  it("each urgency component moves the score in the expected direction", () => {
    const base = makeAssessment("dir-base", {
      confidence: 0.6,
      human_review: false,
      customer: {
        relevance: 0.5,
        priority: "medium",
        reasons: [],
        exposedAssets: 2,
        observed: true,
      },
      evidence: [evidenceRecord("ev-dir", daysAgo(2))],
    });
    const urgency = (
      a: Assessment,
      ctx?: { kev?: boolean; exposedAssets?: number },
    ) => operationalUrgency(a, ctx).urgency;

    // assetImpact: customer priority and exposed assets, both directions.
    const withPriority = (priority: "low" | "medium" | "high" | "critical") =>
      urgency({
        ...base,
        customer: { ...base.customer, priority },
      });
    expect(withPriority("critical")).toBeGreaterThan(withPriority("high"));
    expect(withPriority("high")).toBeGreaterThan(withPriority("medium"));
    expect(withPriority("medium")).toBeGreaterThan(withPriority("low"));
    expect(urgency(base, { exposedAssets: 9 })).toBeGreaterThan(
      urgency(base, { exposedAssets: 1 }),
    );

    // exposure: customer relevance and workspace observation.
    const withRelevance = (relevance: number) =>
      urgency({ ...base, customer: { ...base.customer, relevance } });
    expect(withRelevance(0.9)).toBeGreaterThan(withRelevance(0.1));
    expect(
      urgency({
        ...base,
        customer: { ...base.customer, observed: true },
      }),
    ).toBeGreaterThan(
      urgency({ ...base, customer: { ...base.customer, observed: false } }),
    );

    // freshness: FreshnessState activity tiers, active > stale > expired.
    const observed = (days: number) => [
      { ...evidenceRecord("ev-fresh-" + days, daysAgo(days)) },
    ];
    expect(freshness(observed(2)).activity).toBe("active");
    expect(freshness(observed(STALE_AFTER_DAYS + 5)).activity).toBe("stale");
    expect(freshness(observed(EXPIRES_AFTER_DAYS + 5)).activity).toBe("expired");
    const withAge = (days: number) =>
      urgency({ ...base, evidence: observed(days) });
    expect(withAge(2)).toBeGreaterThan(withAge(STALE_AFTER_DAYS + 5));
    expect(withAge(STALE_AFTER_DAYS + 5)).toBeGreaterThan(
      withAge(EXPIRES_AFTER_DAYS + 5),
    );
    const freshComponent = (days: number) =>
      operationalUrgency({ ...base, evidence: observed(days) }).components
        .freshness;
    expect(freshComponent(2)).toBe(URGENCY_FRESHNESS_ACTIVITY.active);
    expect(freshComponent(STALE_AFTER_DAYS + 5)).toBe(
      URGENCY_FRESHNESS_ACTIVITY.stale,
    );
    expect(freshComponent(EXPIRES_AFTER_DAYS + 5)).toBe(
      URGENCY_FRESHNESS_ACTIVITY.expired,
    );

    // exploitation: KEV-listed > not checked (unknown) > checked and absent.
    const kevTrue = urgency(base, { kev: true });
    const kevUnknown = urgency(base);
    const kevFalse = urgency(base, { kev: false });
    expect(kevTrue).toBeGreaterThan(kevUnknown);
    expect(kevUnknown).toBeGreaterThan(kevFalse);
    // Evidence carrying the CISA KEV signal is exploitation even without ctx.
    expect(
      operationalUrgency({
        ...base,
        evidence: [evidenceRecord("ev-kev", daysAgo(2), { kev: true })],
      }).components.exploitation,
    ).toBe(1);

    // evidenceConfidence: better supported claims rank higher.
    const withConfidence = (confidence: number) =>
      urgency({ ...base, confidence });
    expect(withConfidence(0.9)).toBeGreaterThan(withConfidence(0.2));

    // reviewState: settled > undecided > awaiting analyst judgment.
    const review = (a: Assessment) => operationalUrgency(a).components.reviewState;
    expect(review({ ...base, status: "confirmed" })).toBe(
      URGENCY_REVIEW_STATE.settled,
    );
    expect(review(base)).toBe(URGENCY_REVIEW_STATE.undecided);
    expect(review({ ...base, human_review: true })).toBe(
      URGENCY_REVIEW_STATE.awaiting_review,
    );
    expect(review({ ...base, status: "needs-investigation" })).toBe(
      URGENCY_REVIEW_STATE.awaiting_review,
    );
  });

  it("SQL queue ordering agrees with operationalUrgency, and urgency cursors round-trip", async () => {
    const p = await tenant("t-priority-parity");
    const fixtures: Assessment[] = [
      makeAssessment("par-active-kev", {
        confidence: 0.8,
        severity: "critical",
        human_review: false,
        malicious: { probability: 0.9, classification: "malicious" },
        customer: {
          relevance: 0.4,
          priority: "critical",
          reasons: [],
          exposedAssets: 7,
          observed: true,
        },
        evidence: [
          evidenceRecord("par-ev-1", daysAgo(1), { kev: true }),
          evidenceRecord("par-ev-2", daysAgo(3)),
        ],
      }),
      makeAssessment("par-stale", {
        confidence: 0.5,
        human_review: true,
        customer: {
          relevance: 0.2,
          priority: "medium",
          reasons: [],
          exposedAssets: 0,
          observed: false,
        },
        evidence: [evidenceRecord("par-ev-3", daysAgo(STALE_AFTER_DAYS + 30))],
      }),
      makeAssessment("par-expired-kev", {
        confidence: 0.9,
        human_review: false,
        status: "needs-investigation",
        customer: {
          relevance: 0.9,
          priority: "low",
          reasons: [],
          exposedAssets: 10,
          observed: true,
        },
        evidence: [
          evidenceRecord("par-ev-4", daysAgo(EXPIRES_AFTER_DAYS + 30), {
            kev: true,
          }),
        ],
      }),
      makeAssessment("par-undated", {
        confidence: 0.3,
        status: "confirmed",
        human_review: false,
        customer: {
          relevance: 0.6,
          priority: "high",
          reasons: [],
          exposedAssets: 2,
          observed: true,
        },
        evidence: [evidenceRecord("par-ev-5", undefined)],
      }),
      makeAssessment("par-offline", {
        confidence: 0.4,
        human_review: false,
        evidence: [
          evidenceRecord("par-ev-6", daysAgo(5), {
            status: "offline",
            malicious: true,
          }),
        ],
      }),
      makeAssessment("par-no-evidence", {
        confidence: 0,
        human_review: true,
        customer: {
          relevance: 0.99,
          priority: "critical",
          reasons: [],
          exposedAssets: 50,
          observed: true,
        },
        evidence: [],
      }),
    ];
    for (const a of fixtures) await save(p, a);

    const rows = await db
      .prepare(`SELECT id,${urgencySql} AS u FROM assessments WHERE tenant_id=?`)
      .bind(p.tenantId)
      .all<{ id: string; u: number }>();
    expect(rows.results.map((r) => r.id).sort()).toEqual(
      fixtures.map((a) => a.assessment_id).sort(),
    );
    for (const row of rows.results) {
      const a = fixtures.find((f) => f.assessment_id === row.id)!;
      // The SQL expression (queue ORDER BY / keyset predicate) and the
      // TypeScript formula produce the same rounded score, row by row.
      expect(row.u).toBe(operationalUrgency(a).urgency);
      // …and the cursor value is that same score.
      const cursor = JSON.parse(
        atob(encodeAssessmentCursor(a, "relevance")),
      ) as { sort: string; value: number };
      expect(cursor.sort).toBe("relevance");
      expect(cursor.value).toBe(row.u);
    }
    // The order definition really is urgency-based.
    expect(assessmentOrders.relevance.column).toBe(urgencySql);
  });

  it("keyset pagination on the urgency sort visits every rankable row exactly once", async () => {
    const p = await tenant("t-priority-pagination");
    const fixtures = Array.from({ length: 5 }, (_, i) =>
      makeAssessment("page-" + i, {
        confidence: 0.2 + i * 0.15,
        human_review: false,
        customer: {
          relevance: 0.1 + i * 0.2,
          priority: i > 2 ? "high" : "medium",
          reasons: [],
          exposedAssets: i,
          observed: i % 2 === 0,
        },
        evidence: [evidenceRecord("page-ev-" + i, daysAgo(i + 1))],
      }),
    );
    const zeroEvidence = makeAssessment("page-no-evidence", {
      customer: {
        relevance: 1,
        priority: "critical",
        reasons: [],
        exposedAssets: 100,
        observed: true,
      },
      evidence: [],
    });
    for (const a of [...fixtures, zeroEvidence]) await save(p, a);

    const expected = fixtures
      .map((a) => ({
        id: a.assessment_id,
        u: operationalUrgency(a).urgency,
      }))
      .sort((x, y) => y.u - x.u || (x.id < y.id ? -1 : 1))
      .map((x) => x.id);

    const seen: string[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 10; page++) {
      // Same convention as the API: fetch limit+1, encode a cursor from the
      // last rendered row when more remain.
      const rows = await repo.assessments(p.tenantId, 3, cursor, {
        view: "all",
        sort: "relevance",
      });
      const visible = rows.slice(0, 2);
      seen.push(...visible.map((a) => a.assessment_id));
      cursor =
        rows.length > 2
          ? encodeAssessmentCursor(visible[1]!, "relevance")
          : undefined;
      if (!cursor) break;
    }
    expect(seen).toEqual(expected);
    expect(new Set(seen).size).toBe(seen.length);
    // Insufficient-evidence items are never ranked on this surface.
    expect(seen).not.toContain(zeroEvidence.assessment_id);
  });
});
