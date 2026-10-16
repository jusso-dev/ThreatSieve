import { describe, it, expect } from "vitest";
import { normalise } from "../packages/intel/src/normalise";
import {
  EnvironmentSchema,
  type EvidenceBundle,
  type Evidence,
} from "../packages/schemas/src/index";
import {
  scoreConfidence,
  reasonCodesFor,
  type SourceReliability,
} from "../packages/scoring/src/index";
import {
  EvaluationDataset,
  SYNTHETIC_CHALLENGE_CAVEAT,
} from "../packages/scoring/src/dataset";

function evidence(
  id: string,
  sourceId: string,
  type: Evidence["type"] = "feed",
): Evidence {
  const now = new Date().toISOString();
  return {
    id,
    type,
    sourceId,
    provenance: {
      sourceId,
      sourceName: sourceId + " test fixture",
      retrievedAt: now,
      redistributable: false,
    },
    data: { malicious: true },
    confidence: 0.9,
    createdAt: now,
    observedAt: now,
    behavioural: false,
  };
}
async function bundle(
  ev: Evidence[],
  truncated = false,
): Promise<EvidenceBundle> {
  return {
    observable: await normalise("test.example"),
    evidence: ev,
    relationships: [],
    attackCandidates: [],
    actorCandidates: [],
    relatedEntities: [],
    customerContext: {
      environment: EnvironmentSchema.parse({}),
      observed: false,
      exposedAssets: 0,
    },
    evidenceVersion: "v1",
    truncated,
  };
}
const threatfox: SourceReliability = {
  id: "threatfox",
  independent_group: "abuse.ch",
  reliability: 0.9,
};
const urlhaus: SourceReliability = {
  id: "urlhaus",
  independent_group: "abuse.ch",
  reliability: 0.9,
};
const tenantTelemetry: SourceReliability = {
  id: "tenant-telemetry",
  independent_group: "customer",
  reliability: 0.8,
};
const codesOf = (factors: { code: string }[]) => factors.map((f) => f.code);

describe("confidence factor codes name what they measure (leaf 1.2.3)", () => {
  it("a single independent source group gets SINGLE_SOURCE_SUPPORT, never MULTI_SOURCE_CONFIRMATION", async () => {
    const b = await bundle([evidence("e1", "threatfox")]);
    const s = scoreConfidence(b, 0.9, 0.8, [threatfox]);
    expect(s.independentSources).toBe(1);
    const codes = codesOf(s.factors);
    expect(codes).toContain("SINGLE_SOURCE_SUPPORT");
    expect(codes).not.toContain("MULTI_SOURCE_CONFIRMATION");
  });
  it("MULTI_SOURCE_CONFIRMATION requires two independent source groups", async () => {
    const b = await bundle([
      evidence("e1", "threatfox"),
      evidence("e2", "tenant-telemetry", "telemetry"),
    ]);
    const s = scoreConfidence(b, 0.9, 0.8, [threatfox, tenantTelemetry]);
    expect(s.independentSources).toBe(2);
    const codes = codesOf(s.factors);
    expect(codes).toContain("MULTI_SOURCE_CONFIRMATION");
    expect(codes).not.toContain("SINGLE_SOURCE_SUPPORT");
  });
  it("mirrored sources in one independence group do not confirm each other", async () => {
    const b = await bundle([
      evidence("e1", "threatfox"),
      evidence("e2", "urlhaus"),
    ]);
    const s = scoreConfidence(b, 0.9, 0.8, [threatfox, urlhaus]);
    expect(s.independentSources).toBe(1);
    const codes = codesOf(s.factors);
    expect(codes).toContain("SINGLE_SOURCE_SUPPORT");
    expect(codes).not.toContain("MULTI_SOURCE_CONFIRMATION");
  });
  it("the reliability factor is named for reliability, not source multiplicity", async () => {
    const b = await bundle([evidence("e1", "threatfox")]);
    const s = scoreConfidence(b, 0.9, 0.8, [threatfox]);
    const reliability = s.factors.find((f) => f.weight === 0.35);
    expect(reliability?.code).toBe("EVIDENCE_RELIABILITY");
    // mean(evidence confidence 0.9 × source reliability 0.9)
    expect(reliability?.value).toBeCloseTo(0.81);
  });
  it("evidence strength and classifier decisiveness are not LOW_EVIDENCE", async () => {
    const b = await bundle([evidence("e1", "threatfox")]);
    const s = scoreConfidence(b, 0.8, 0.5, [threatfox]);
    const strength = s.factors.find(
      (f) => f.weight === 0.2 && f.code === "EVIDENCE_STRENGTH",
    );
    expect(strength?.value).toBeCloseTo(0.5);
    const decisiveness = s.factors.find(
      (f) => f.weight === 0.2 && f.code === "CLASSIFIER_DECISIVENESS",
    );
    expect(decisiveness?.value).toBeCloseTo(0.8);
    expect(codesOf(s.factors)).not.toContain("LOW_EVIDENCE");
  });
  it("direct observation evidence is DIRECT_EVIDENCE, not CUSTOMER_OBSERVED", async () => {
    const withDirect = scoreConfidence(
      await bundle([evidence("e1", "tenant-telemetry", "telemetry")]),
      0.9,
      0.8,
      [tenantTelemetry],
    );
    const direct = withDirect.factors.find((f) => f.code === "DIRECT_EVIDENCE");
    expect(direct?.value).toBe(1);
    expect(codesOf(withDirect.factors)).not.toContain("CUSTOMER_OBSERVED");
  });
  it("a truncated bundle is TRUNCATED_EVIDENCE; an empty bundle is LOW_EVIDENCE", async () => {
    const truncated = scoreConfidence(
      await bundle([evidence("e1", "threatfox")], true),
      0.9,
      0.8,
      [threatfox],
    );
    const penalty = truncated.factors.find((f) => f.weight === -0.2);
    expect(penalty?.code).toBe("TRUNCATED_EVIDENCE");
    const empty = scoreConfidence(await bundle([]), 0.9, 0.8, [threatfox]);
    const codes = codesOf(empty.factors);
    expect(codes).toContain("LOW_EVIDENCE");
    expect(codes).not.toContain("MULTI_SOURCE_CONFIRMATION");
    expect(codes).not.toContain("SINGLE_SOURCE_SUPPORT");
  });
  it("assessment reason codes follow the same multi/single source rule", async () => {
    const b = await bundle([evidence("e1", "threatfox")]);
    const single = reasonCodesFor(b, 1);
    expect(single).toContain("SINGLE_SOURCE_SUPPORT");
    expect(single).not.toContain("MULTI_SOURCE_CONFIRMATION");
    expect(single).not.toContain("SINGLE_SOURCE_ONLY");
    const multi = reasonCodesFor(b, 2);
    expect(multi).toContain("MULTI_SOURCE_CONFIRMATION");
    expect(multi).not.toContain("SINGLE_SOURCE_SUPPORT");
    const none = reasonCodesFor(await bundle([]), 0);
    expect(none).toContain("LOW_EVIDENCE");
    expect(none).not.toContain("MULTI_SOURCE_CONFIRMATION");
    expect(none).not.toContain("SINGLE_SOURCE_SUPPORT");
  });
});

describe("evaluation dataset hygiene (leaf 1.2.3)", () => {
  const dataset = async (kind: "synthetic-challenge" | "analyst-labelled") => ({
    version: "1.0" as const,
    kind,
    sampling:
      kind === "analyst-labelled"
        ? {
            population: "Independent reviewed cases for the test population",
            method: "Stratified random held-out sample by source",
            exclusions: "Mirrored duplicate source reports excluded",
            heldOut: true as const,
          }
        : undefined,
    description: "Evaluation cases for label hygiene checks",
    cases: [
      {
        id: "case-1",
        category: "maliciousness" as const,
        label: 1 as const,
        rationale: "Stipulated label used only for schema hygiene checks",
        reviewedBy: "Test fixture",
        reviewedAt: new Date().toISOString(),
        bundle: {
          observable: await normalise("unknown.example"),
          evidence: [],
          relationships: [],
          attackCandidates: [],
          actorCandidates: [],
          relatedEntities: [],
          customerContext: {
            environment: EnvironmentSchema.parse({}),
            observed: false,
            exposedAssets: 0,
          },
          evidenceVersion: "synthetic-1",
          truncated: false,
        },
      },
    ],
  });
  it("a synthetic-challenge dataset never reaches a report without a caveat", async () => {
    const parsed = EvaluationDataset.parse(
      await dataset("synthetic-challenge"),
    );
    expect(parsed.caveat).toBe(SYNTHETIC_CHALLENGE_CAVEAT);
    expect(parsed.caveat).toMatch(/[Nn]ot .*accuracy|must not be claimed/);
  });
  it("a producer-supplied caveat is preserved", async () => {
    const d = {
      ...(await dataset("synthetic-challenge")),
      caveat: "Probe suite only: no accuracy claim may be made from this run.",
    };
    expect(EvaluationDataset.parse(d).caveat).toBe(d.caveat);
  });
  it("an analyst-labelled dataset is not force-caveated", async () => {
    const parsed = EvaluationDataset.parse(await dataset("analyst-labelled"));
    expect(parsed.caveat).toBeUndefined();
  });
});
