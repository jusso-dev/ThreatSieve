import { z } from "zod";
import {
  ObservableSchema,
  EvidenceSchema,
  RelationshipSchema,
  CandidateSchema,
  EntitySchema,
  EnvironmentSchema,
} from "../../schemas/src/index";
/** leaf-1.2.3 additive: canonical caveat filled into synthetic-challenge
 * datasets that omit one. Headline accuracy must not be claimed from them. */
export const SYNTHETIC_CHALLENGE_CAVEAT =
  "Synthetic challenge cases are robustness probes, not a real-world accuracy or calibration dataset. Headline accuracy must not be claimed from these results.";
export const EvaluationCase = z
  .object({
    id: z.string().min(1).max(100),
    category: z.enum(["maliciousness", "actor"]),
    // Unknown labels test escalation, never contribute fabricated negative truth.
    label: z.union([z.literal(0), z.literal(1), z.null()]),
    actorId: z.string().optional(),
    rationale: z.string().min(10).max(2000),
    reviewedBy: z.string().min(1).max(200),
    reviewedAt: z.iso.datetime(),
    bundle: z.object({
      observable: ObservableSchema,
      evidence: z.array(EvidenceSchema).max(100),
      relationships: z.array(RelationshipSchema).max(200),
      attackCandidates: z.array(CandidateSchema).max(20),
      actorCandidates: z.array(CandidateSchema).max(10),
      relatedEntities: z.array(EntitySchema).max(100),
      customerContext: z.object({
        environment: EnvironmentSchema,
        observed: z.boolean(),
        exposedAssets: z.number().int().nonnegative(),
      }),
      evidenceVersion: z.string(),
      truncated: z.boolean(),
    }),
  })
  .superRefine((item, ctx) => {
    if (
      item.category === "actor" &&
      !item.bundle.actorCandidates.some((c) => c.id === item.actorId)
    )
      ctx.addIssue({
        code: "custom",
        message: "Actor evaluation requires an existing bounded candidate",
      });
    const ids = new Set(item.bundle.evidence.map((e) => e.id));
    for (const c of [
      ...item.bundle.attackCandidates,
      ...item.bundle.actorCandidates,
    ])
      if (c.evidenceIds.some((id) => !ids.has(id)))
        ctx.addIssue({
          code: "custom",
          message: "Candidate references missing evidence",
        });
  });
export const EvaluationDataset = z
  .object({
    version: z.literal("1.0"),
    kind: z.enum(["synthetic-challenge", "analyst-labelled"]),
    description: z.string().min(10),
    // leaf-1.2.3 additive: a dataset that reaches a report must carry its own
    // caveat. Producers may supply one; see the transform below.
    caveat: z.string().trim().min(10).optional(),
    cases: z.array(EvaluationCase).min(1).max(100),
  })
  .superRefine((d, ctx) => {
    if (new Set(d.cases.map((c) => c.id)).size !== d.cases.length)
      ctx.addIssue({ code: "custom", message: "Case IDs must be unique" });
  })
  // leaf-1.2.3 additive: evaluation hygiene. Headline accuracy must never be
  // reported from a synthetic-challenge dataset without a caveat — these cases
  // measure bounded robustness behaviour, not real-world accuracy or
  // calibration. The schema refuses to yield an uncaveated synthetic dataset:
  // when the producer omitted `caveat`, the canonical refusal text is filled
  // in so every downstream report quotes the caveat with its numbers.
  .transform((d) =>
    d.kind === "synthetic-challenge" && !d.caveat
      ? { ...d, caveat: SYNTHETIC_CHALLENGE_CAVEAT }
      : d,
  );
