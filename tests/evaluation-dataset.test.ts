import { it, expect } from "vitest";
import { EvaluationDataset } from "../packages/scoring/src/dataset";
import { normalise } from "../packages/intel/src/normalise";
const example = async () => ({
  version: "1.0",
  kind: "synthetic-challenge",
  description: "Synthetic unlabelled review case",
  cases: [
    {
      id: "unknown",
      category: "maliciousness",
      label: null,
      rationale: "Unknown is not a confirmed benign label",
      reviewedBy: "Synthetic specification",
      reviewedAt: new Date().toISOString(),
      bundle: {
        observable: await normalise("unknown.example"),
        evidence: [],
        relationships: [],
        attackCandidates: [],
        actorCandidates: [],
        relatedEntities: [],
        customerContext: { environment: {}, observed: false, exposedAssets: 0 },
        evidenceVersion: "synthetic-1",
        truncated: false,
      },
    },
  ],
});
it("keeps unknown labels separate and rejects duplicate evaluation IDs", async () => {
  const d = await example();
  expect(EvaluationDataset.parse(d).cases[0]?.label).toBeNull();
  d.cases.push(d.cases[0]!);
  expect(EvaluationDataset.safeParse(d).success).toBe(false);
});
it("requires an existing candidate and evidence references for actor evaluation", async () => {
  const d = await example();
  d.cases[0]!.category = "actor";
  expect(EvaluationDataset.safeParse(d).success).toBe(false);
});
