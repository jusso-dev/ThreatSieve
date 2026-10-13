import { migrationStatements } from "../packages/database/src/migrations";
import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import { Repository } from "../packages/database/src/repository";
import {
  automaticGatesPassed,
  effectiveClassificationSql,
  effectiveDecision,
  effectiveRecommendations,
} from "../packages/database/src/decision-state";
import {
  attentionPredicate,
  reviewPredicate,
} from "../packages/database/src/assessment-query";
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

function evidenceRecord(id: string, observedAt: string): Evidence {
  return {
    id,
    type: "feed",
    sourceId: "threatfox",
    provenance: {
      sourceId: "threatfox",
      sourceName: "ThreatFox",
      retrievedAt: observedAt,
      redistributable: true,
    },
    data: { malicious: true },
    confidence: 0.9,
    createdAt: observedAt,
    observedAt,
    behavioural: true,
  };
}

/** The audit's reproduction case: model output is unknown with 0% confidence. */
function modelAssessment(
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

describe("one effective analyst decision (audit finding 4)", () => {
  it("benign override then confirm yields one coherent analyst-confirmed benign state", async () => {
    const p = await tenant("t-audit");
    const original = modelAssessment("audit-contradiction");
    await save(p, original);

    // Analyst submits a benign override (modify → benign), then confirms.
    const modified = await repo.feedback(
      p,
      original.assessment_id,
      "modified",
      "malicious",
      "benign",
      "Verified legitimate infrastructure",
      "corr-modify",
    );
    expect(modified.effective_classification).toBe("benign");
    // The override drives recommendations immediately — no stale INVESTIGATE.
    expect(effectiveRecommendations(modified).map((x) => x.action)).toEqual([
      "ignore",
    ]);
    expect(modified.recommended_actions).toEqual(
      effectiveRecommendations(modified),
    );
    // The unconfirmed override still awaits confirmation in the queue.
    const awaiting = await repo.assessments(p.tenantId, 50, undefined, {
      view: "attention",
    });
    expect(awaiting.map((x) => x.assessment_id)).toContain(
      original.assessment_id,
    );

    const confirmed = await repo.feedback(
      p,
      original.assessment_id,
      "confirmed",
      "assessment",
      undefined,
      "Confirmed benign after review",
      "corr-confirm",
    );
    expect(confirmed.status).toBe("confirmed");
    const state = (await repo.assessment(
      p.tenantId,
      original.assessment_id,
    ))!;

    // Wording source: "Analyst confirmed: benign (decidedAt)".
    const decision = effectiveDecision(state);
    expect(decision).toEqual({
      classification: "benign",
      role: "unknown",
      source: "analyst",
      decidedAt: state.analyst_decision!.createdAt,
    });

    // Recommended actions agree with the decision: nothing to investigate or block.
    const actions = effectiveRecommendations(state).map((x) => x.action);
    expect(actions).toEqual(["ignore"]);
    expect(actions).not.toContain("investigate");
    expect(actions).not.toContain("block");
    expect(state.recommended_actions.map((x) => x.action)).toEqual(actions);
    // Benign decisions monitor indicators the customer actually observed.
    expect(
      effectiveRecommendations({
        ...state,
        customer: { ...state.customer, observed: true },
      }).map((x) => x.action),
    ).toEqual(["monitor"]);

    // "Confidence gates passed" is never claimed: the cleared review flag is a
    // human decision, not an automatic gate result, at 0% confidence with zero
    // evidence.
    expect(state.human_review).toBe(false);
    expect(automaticGatesPassed(state)).toBe(false);

    // Queue placement: confirmed benign is out of the attention queue.
    const attention = await repo.assessments(p.tenantId, 50, undefined, {
      view: "attention",
    });
    expect(attention.map((x) => x.assessment_id)).not.toContain(
      original.assessment_id,
    );
    const review = await repo.assessments(p.tenantId, 50, undefined, {
      view: "review",
    });
    expect(review.map((x) => x.assessment_id)).not.toContain(
      original.assessment_id,
    );
    expect((await repo.assessmentSummary(p.tenantId)).summary.attention).toBe(
      0,
    );

    // The model's original output is history and is never overwritten.
    expect(state.malicious).toEqual(original.malicious);
    expect(state.confidence).toBe(0);
    expect(state.confidence_factors).toEqual(original.confidence_factors);
    expect(state.models).toEqual(original.models);
    expect(state.runs).toEqual(original.runs);
  });

  it("a confirmation carrying an override is rejected as a modification in disguise", async () => {
    const p = await tenant("t-smuggle");
    const original = modelAssessment("smuggled-override");
    await save(p, original);
    await expect(
      repo.feedback(
        p,
        original.assessment_id,
        "confirmed",
        "malicious",
        "benign",
        "Override smuggled into a confirmation",
        "corr-smuggle",
      ),
    ).rejects.toMatchObject({ code: "INVALID_OVERRIDE", status: 422 });
    // Nothing changed: the state and the audit trail cannot disagree.
    const state = (await repo.assessment(
      p.tenantId,
      original.assessment_id,
    ))!;
    expect(state.status).toBe("pending");
    expect(state.revision ?? 0).toBe(0);
    expect(state.effective_classification).toBeUndefined();
    expect(effectiveDecision(state).source).toBe("model");
    expect(
      (
        await db
          .prepare(
            "SELECT COUNT(*) AS n FROM analyst_feedback WHERE tenant_id=?",
          )
          .bind(p.tenantId)
          .first<{ n: number }>()
      )?.n,
    ).toBe(0);
  });

  it("a second analyst decision replaces the first while the audit trail keeps every step", async () => {
    const p = await tenant("t-second");
    const id = "second-decision";
    const original = modelAssessment(id);
    await save(p, original);
    const first = await repo.feedback(
      p,
      id,
      "modified",
      "malicious",
      "benign",
      "First decision: benign",
      "corr-first",
    );
    const second = await repo.feedback(
      p,
      id,
      "modified",
      "malicious",
      "malicious",
      "Second decision: actually malicious",
      "corr-second",
    );
    const state = (await repo.assessment(p.tenantId, id))!;
    // Exactly one effective decision at a time: the latest analyst decision wins.
    expect(effectiveDecision(state)).toEqual({
      classification: "malicious",
      role: "unknown",
      source: "analyst",
      decidedAt: state.analyst_decision!.createdAt,
    });
    expect(state.analyst_decision?.reason).toBe(
      "Second decision: actually malicious",
    );
    expect(second.analyst_decision?.createdAt).not.toBe(
      first.analyst_decision?.createdAt,
    );
    // The audit trail retains full history.
    const rows = await db
      .prepare(
        "SELECT field,analyst_value,reason FROM analyst_feedback WHERE tenant_id=? AND assessment_id=? ORDER BY created_at,id",
      )
      .bind(p.tenantId, id)
      .all<{ field: string; analyst_value: string; reason: string }>();
    expect(rows.results.map((r) => JSON.parse(r.analyst_value))).toEqual([
      "benign",
      "malicious",
    ]);
    expect(rows.results.map((r) => r.reason)).toEqual([
      "First decision: benign",
      "Second decision: actually malicious",
    ]);
    // Model history untouched.
    expect(state.malicious).toEqual(original.malicious);
    // Confirmation after modification resolves the single effective decision.
    await repo.feedback(
      p,
      id,
      "confirmed",
      "assessment",
      undefined,
      "Confirmed after modification",
      "corr-confirm-second",
    );
    const confirmed = (await repo.assessment(p.tenantId, id))!;
    expect(confirmed.status).toBe("confirmed");
    expect(effectiveDecision(confirmed).classification).toBe("malicious");
    // Confirmed malicious per evidence: no evidence, so no block recommendation.
    expect(effectiveRecommendations(confirmed).map((x) => x.action)).toEqual([
      "hunt",
    ]);
  });

  it("confirmed malicious recommends block/hunt per evidence, gated by freshness", async () => {
    const p = await tenant("t-malicious");
    const now = new Date().toISOString();
    const fresh = modelAssessment("confirmed-malicious", {
      malicious: { probability: 0.97, classification: "malicious" },
      role: { value: "c2", probability: 0.9 },
      severity: "high",
      confidence: 0.9,
      recommended_actions: [
        { action: "investigate", confidence: 0.9, reason_codes: [] },
      ],
      evidence: [evidenceRecord("ev-fresh", now)],
      reason_codes: ["KNOWN_C2"],
    });
    await save(p, fresh);
    await repo.feedback(
      p,
      fresh.assessment_id,
      "modified",
      "malicious",
      "malicious",
      "Confirmed malicious classification",
      "corr-malicious-modify",
    );
    const confirmed = await repo.feedback(
      p,
      fresh.assessment_id,
      "confirmed",
      "assessment",
      undefined,
      "Confirmed malicious after review",
      "corr-malicious-confirm",
    );
    expect(effectiveRecommendations(confirmed).map((x) => x.action)).toEqual([
      "block",
      "hunt",
    ]);
    expect(confirmed.recommended_actions.map((x) => x.action)).toEqual([
      "block",
      "hunt",
    ]);
    // An analyst decision is never an automatic gate result.
    expect(automaticGatesPassed(confirmed)).toBe(false);

    // Stale evidence can never justify blocking: the block is downgraded.
    const staleActions = effectiveRecommendations(
      modelAssessment("stale-malicious", {
        status: "confirmed",
        malicious: { probability: 0.97, classification: "malicious" },
        confidence: 0.9,
        human_review: false,
        evidence: [
          evidenceRecord(
            "ev-stale",
            new Date(Date.now() - 40 * 86400000).toISOString(),
          ),
        ],
      }),
    );
    expect(staleActions.map((x) => x.action)).toEqual(["hunt"]);
    for (const action of staleActions)
      expect(action.reason_codes).toContain("FRESH_EVIDENCE_REQUIRED");
  });

  it("anything awaiting analyst review is investigated, or enriched without evidence", () => {
    const withEvidence = modelAssessment("awaiting-evidence", {
      evidence: [evidenceRecord("ev-await", new Date().toISOString())],
    });
    expect(effectiveRecommendations(withEvidence).map((x) => x.action)).toEqual(
      ["investigate"],
    );
    const noEvidence = modelAssessment("awaiting-empty");
    expect(effectiveRecommendations(noEvidence).map((x) => x.action)).toEqual([
      "enrich",
    ]);
    // A zero-evidence, zero-confidence assessment can never claim gates passed.
    expect(automaticGatesPassed(noEvidence)).toBe(false);
  });

  it("gates-passed wording is reserved for model-driven auto-accept", () => {
    const auto = modelAssessment("auto-accepted", {
      malicious: { probability: 0.97, classification: "malicious" },
      confidence: 0.9,
      human_review: false,
      human_review_probability: 0.05,
      evidence: [evidenceRecord("ev-auto", new Date().toISOString())],
    });
    expect(automaticGatesPassed(auto)).toBe(true);
    // Zero evidence / zero confidence: never an automatic gate result.
    expect(
      automaticGatesPassed(modelAssessment("empty", { human_review: false })),
    ).toBe(false);
    // An analyst decision is never an automatic gate result.
    expect(
      automaticGatesPassed({ ...auto, status: "confirmed", human_review: false }),
    ).toBe(false);
  });

  it("queue predicates and classification filters agree with the effective decision", async () => {
    const p = await tenant("t-queue");
    const original = modelAssessment("queue-consistency");
    await save(p, original);
    // The SQL surfaces coalesce the analyst override over model output through
    // decision-state.ts — the single source of truth.
    expect(attentionPredicate).toContain(effectiveClassificationSql);
    expect(reviewPredicate).toContain("status!='confirmed'");
    await repo.feedback(
      p,
      original.assessment_id,
      "modified",
      "malicious",
      "benign",
      "Analyst override to benign",
      "corr-queue",
    );
    const benignRows = await repo.assessments(p.tenantId, 50, undefined, {
      classification: "benign",
    });
    expect(benignRows.map((x) => x.assessment_id)).toEqual([
      original.assessment_id,
    ]);
    const unknownRows = await repo.assessments(p.tenantId, 50, undefined, {
      classification: "unknown",
    });
    expect(unknownRows.map((x) => x.assessment_id)).toEqual([]);
  });
});
