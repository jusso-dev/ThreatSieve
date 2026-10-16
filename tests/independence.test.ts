import { expect, it } from "vitest";
import {
  independentSourceCount,
  upstreamIdentity,
} from "../packages/scoring/src/independence";
import { annotateMirroredAssertions } from "../packages/database/src/canonical";
import { scoreConfidence } from "../packages/scoring/src/index";
import { normalise } from "../packages/intel/src/normalise";
import {
  EnvironmentSchema,
  type Evidence,
  type EvidenceBundle,
} from "../packages/schemas/src/index";
import type { SourceProvenance } from "../packages/schemas/src/index";
const source = (
  id: string,
  extra: Partial<SourceProvenance> = {},
): SourceProvenance => ({
  sourceId: id,
  sourceName: id,
  sourceRecordId: "42",
  retrievedAt: "2026-01-01T00:00:00.000Z",
  redistributable: true,
  ...extra,
});
it("equal provider-local IDs remain independent and declared mirrors do not", () => {
  const a = source("a"),
    b = source("b");
  expect(upstreamIdentity(a)).not.toBe(upstreamIdentity(b));
  expect(annotateMirroredAssertions([a, b])).toMatchObject({
    mirror_count: 0,
    independent_corroboration_count: 2,
  });
  const mirrored = [
    source("a", { sourceRecordNamespace: "producer" }),
    source("b", { sourceRecordNamespace: "producer" }),
  ];
  expect(annotateMirroredAssertions(mirrored)).toMatchObject({
    mirror_count: 1,
    independent_corroboration_count: 1,
  });
});
it("one policy model collapses configured groups and transitive mirrors", () => {
  const policies = [
    { id: "a", independent_group: "shared" },
    { id: "c", independent_group: "shared" },
  ];
  const ps = [
    source("a", { sourceRecordNamespace: "origin" }),
    source("b", { sourceRecordNamespace: "origin" }),
    source("c", { sourceRecordId: "different" }),
  ];
  expect(independentSourceCount(ps, policies)).toBe(1);
  expect(
    annotateMirroredAssertions(ps, policies).independent_corroboration_count,
  ).toBe(1);
});
it("classifier confidence uses explicit original producer identity", async () => {
  const make = (id: string): Evidence => ({
    id: "e-" + id,
    sourceId: id,
    type: "feed",
    data: { malicious: true },
    confidence: 0.8,
    behavioural: false,
    createdAt: "2026-01-01T00:00:00.000Z",
    provenance: source(id, { originalSourceId: "producer" }),
  });
  const input: EvidenceBundle = {
    observable: await normalise("independent.example"),
    evidence: [make("a"), make("b")],
    relationships: [],
    attackCandidates: [],
    actorCandidates: [],
    relatedEntities: [],
    evidenceVersion: "v1",
    truncated: false,
    customerContext: {
      environment: EnvironmentSchema.parse({}),
      observed: false,
      exposedAssets: 0,
    },
  };
  const result = scoreConfidence(input, 0.9, 0.8, []);
  expect(result.independentSources).toBe(1);
});

it("a declared redistributor shares credit with the native producer", () => {
  expect(
    independentSourceCount([
      source("producer"),
      source("mirror", {
        originalSourceId: "producer",
        sourceRecordId: "different-report",
      }),
    ]),
  ).toBe(1);
});
