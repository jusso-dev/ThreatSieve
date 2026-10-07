import { Repository } from "../../packages/database/src/repository";
import {
  buildEvidenceBundle,
  retrieveSemanticCandidates,
} from "../../packages/attack/src/candidates";
import {
  ClefDecisionEngine,
  WorkersAITransport,
  cacheKey,
  FLASH,
  FULL,
  DEFAULT_THRESHOLDS,
  type DecisionTransport,
} from "../../packages/clef/src/index";
import type { AppEnv } from "../../apps/api/src/env";
import { sourceReliabilities } from "../../packages/enterprise/src/sources";
import { AppError } from "../../packages/observability/src/index";
import { z } from "zod";
import { digest, canonicalJson } from "../../packages/intel/src/normalise";
export async function classify(
  env: AppEnv,
  tenantId: string,
  entityId: string,
  force = false,
  transport?: DecisionTransport,
) {
  const repo = new Repository(env.DB);
  const bundle = await buildEvidenceBundle(repo, tenantId, entityId);
  if (env.VECTORIZE_ENABLED === "true")
    await retrieveSemanticCandidates(
      repo,
      bundle,
      env.VECTOR_INDEX,
      {
        async embed(text) {
          const output = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
            text: [text],
          });
          return z.object({ data: z.array(z.array(z.number())) }).parse(output)
            .data[0]!;
        },
      },
      tenantId,
    );
  const sources = { results: await sourceReliabilities(env.DB, tenantId) };
  bundle.evidenceVersion = await digest(
    canonicalJson({
      evidence: bundle.evidenceVersion,
      sources: sources.results,
      policy: [
        env.AUTO_ACCEPT_THRESHOLD,
        env.REVIEW_THRESHOLD,
        env.ATTACK_ACCEPT_THRESHOLD,
        env.ATTACK_PROBABLE_THRESHOLD,
        env.ATTACK_WEAK_THRESHOLD,
      ],
    }),
  );
  const keys = await Promise.all([
    cacheKey(tenantId, bundle, FLASH),
    cacheKey(tenantId, bundle, FULL),
  ]);
  if (!force) {
    const cached = await repo.cached(tenantId, keys[0]!);
    if (cached) return cached;
  }
  const budget = await env.DB.prepare(
    "INSERT INTO inference_budget(tenant_id,day,count) VALUES(?,?,1) ON CONFLICT(tenant_id,day) DO UPDATE SET count=count+1 WHERE count<? RETURNING count",
  )
    .bind(
      tenantId,
      new Date().toISOString().slice(0, 10),
      Number(env.DAILY_CLASSIFICATION_LIMIT),
    )
    .first();
  if (!budget)
    throw new AppError(
      "AI_BUDGET_EXHAUSTED",
      429,
      "Daily classification budget reached",
    );
  const engine = new ClefDecisionEngine(
    transport ?? new WorkersAITransport(env.AI),
    {
      ...DEFAULT_THRESHOLDS,
      autoAccept: Number(env.AUTO_ACCEPT_THRESHOLD),
      review: Number(env.REVIEW_THRESHOLD),
      attackAccept: Number(env.ATTACK_ACCEPT_THRESHOLD),
      attackProbable: Number(env.ATTACK_PROBABLE_THRESHOLD),
      attackWeak: Number(env.ATTACK_WEAK_THRESHOLD),
    },
  );
  const assessment = await engine.classifyObservable(bundle, sources.results);
  await repo.saveAssessment(tenantId, assessment, keys);
  return assessment;
}
