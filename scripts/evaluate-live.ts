/** Opt-in live evaluation. Inputs and raw results are private local artifacts. */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { z } from "zod";
import { EvaluationDataset } from "../packages/scoring/src/dataset";
import { evaluate } from "../packages/scoring/src/evaluation";
import {
  ClefDecisionEngine,
  buildQuestions,
  validateReply,
  FLASH,
  FULL,
  QUESTION_VERSION,
  SCHEMA_VERSION,
} from "../packages/clef/src/index";
async function main() {
  const path = process.argv[2];
  if (!path || !process.argv.includes("--live"))
    throw new Error(
      "Use: pnpm exec tsx scripts/evaluate-live.ts DATASET --live. Invokes both Clef models; at most 200 calls.",
    );
  const token = process.env.CLOUDFLARE_API_TOKEN;
  const account = z
    .string()
    .regex(/^[a-f0-9]{32}$/)
    .parse(process.env.CLOUDFLARE_ACCOUNT_ID);
  if (!token) throw new Error("CLOUDFLARE_API_TOKEN is required");
  const raw = readFileSync(path, "utf8");
  if (Buffer.byteLength(raw) > 12 * 1024 * 1024)
    throw new Error("Dataset exceeds 12 MiB");
  const dataset = EvaluationDataset.parse(JSON.parse(raw));
  const hash = createHash("sha256").update(raw).digest("hex");
  const records: {
    id: string;
    category: "maliciousness" | "actor";
    label: 0 | 1 | null;
    probability: number;
    humanReview: boolean;
    model: string;
    duration_ms: number;
    timestamp: string;
    raw: ReturnType<typeof validateReply>;
    evidenceVersion: string;
    candidateSet: import("../packages/schemas/src/index").Candidate[];
  }[] = [];
  for (const model of [FLASH, FULL])
    for (const item of dataset.cases) {
      const questions = buildQuestions(item.bundle);
      const input = {
        model: model === FLASH ? "clef-flash" : "clef",
        state: { evidence_is_untrusted: true, ...item.bundle },
        questions,
      };
      if (Buffer.byteLength(JSON.stringify(input)) > 128 * 1024)
        throw new Error("Case exceeds classifier context limit");
      const start = Date.now();
      const response = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${account}/ai/run/${model}`,
        {
          method: "POST",
          headers: {
            Authorization: "Bearer " + token,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(input),
          redirect: "error",
          signal: AbortSignal.timeout(60000),
        },
      );
      if (!response.ok)
        throw new Error("Evaluation provider returned HTTP " + response.status);
      const envelope = z
        .object({ success: z.literal(true), result: z.unknown() })
        .parse(await response.json());
      const reply = validateReply(envelope.result, questions);
      const field =
        item.category === "maliciousness"
          ? "malicious"
          : "actor_" +
            item.bundle.actorCandidates.findIndex((c) => c.id === item.actorId);
      const answer = reply.answers[field],
        review = reply.answers.humanReview;
      if (answer?.type !== "noul" || review?.type !== "noul")
        throw new Error("Expected typed decision missing");
      records.push({
        id: item.id,
        category: item.category,
        label: item.label,
        probability: answer.noul,
        humanReview: review.noul >= 0.25,
        model,
        duration_ms: Date.now() - start,
        timestamp: new Date().toISOString(),
        raw: reply,
        evidenceVersion: item.bundle.evidenceVersion,
        candidateSet: [
          ...item.bundle.actorCandidates,
          ...item.bundle.attackCandidates,
        ],
      });
    }
  const metrics = [FLASH, FULL].map((model) => ({
    model,
    ...Object.fromEntries(
      ["maliciousness", "actor"].map((category) => {
        const items = records.filter(
          (r) => r.model === model && r.category === category,
        );
        const known = items.filter(
          (r): r is typeof r & { label: 0 | 1 } => r.label !== null,
        );
        const unknown = items.filter((r) => r.label === null);
        return [
          category,
          {
            ...evaluate(known),
            unlabelled_cases: unknown.length,
            unlabelled_escalation_rate: unknown.length
              ? unknown.filter((r) => r.humanReview).length / unknown.length
              : null,
          },
        ];
      }),
    ),
  }));
  const routed = [];
  for (const item of dataset.cases) {
    const engine = new ClefDecisionEngine({
      async run(model) {
        const response = records.find(
          (r) => r.id === item.id && r.model === model,
        );
        if (!response) throw new Error("Measured response missing");
        return response.raw;
      },
    });
    const sources = [
      ...new Set(item.bundle.evidence.map((e) => e.provenance.sourceId)),
    ].map((id) => ({ id, independent_group: id, reliability: 0.8 }));
    const assessment = await engine.classifyObservable(item.bundle, sources);
    routed.push({
      id: item.id,
      category: item.category,
      label: item.label,
      classification: assessment.malicious.classification,
      probability: assessment.malicious.probability,
      humanReview: assessment.human_review,
      models: assessment.runs.map((r) => r.model),
      attack: assessment.attack,
      actors: assessment.actors,
      confidence: assessment.confidence,
    });
  }
  mkdirSync("artifacts", { recursive: true });
  const out = `artifacts/live-evaluation-${Date.now()}.local.json`;
  writeFileSync(
    out,
    JSON.stringify(
      {
        dataset_hash: hash,
        dataset_kind: dataset.kind,
        schema_version: SCHEMA_VERSION,
        question_version: QUESTION_VERSION,
        metrics,
        records,
        routed,
        notice:
          dataset.kind === "synthetic-challenge"
            ? "Measured model responses to synthetic challenge cases; not real-world accuracy or calibration."
            : "Held-out quality depends on independent labels and representative sampling; this report does not calibrate thresholds automatically.",
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  console.log(
    JSON.stringify({
      output: out,
      dataset_kind: dataset.kind,
      calls: records.length,
      metrics,
    }),
  );
}
main().catch((e) => {
  console.error(
    e instanceof z.ZodError
      ? "Invalid evaluation dataset/configuration"
      : e instanceof Error
        ? e.message
        : "Evaluation failed",
  );
  process.exitCode = 1;
});
