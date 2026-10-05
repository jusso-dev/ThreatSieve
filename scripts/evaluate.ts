import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { z } from "zod";
import { evaluate } from "../packages/scoring/src/evaluation";
const args = process.argv.slice(2);
const argument = (key: string) => {
  const i = args.indexOf(key);
  return i >= 0 ? args[i + 1] : undefined;
};
const cases = z
  .array(
    z.object({
      id: z.string(),
      category: z.enum(["maliciousness", "actor"]),
      label: z.union([z.literal(0), z.literal(1)]),
    }),
  )
  .parse(
    JSON.parse(readFileSync("tests/fixtures/evaluation/cases.json", "utf8")),
  );
const Predictions = z.object({
  kind: z.string(),
  model: z.string(),
  predictions: z.array(
    z.object({
      id: z.string(),
      probability: z.number().min(0).max(1),
      humanReview: z.boolean(),
    }),
  ),
});
const currentPath =
  argument("--current") ?? "tests/fixtures/evaluation/recorded-baseline.json";
const candidatePath = argument("--candidate") ?? currentPath;
function report(path: string) {
  const output = Predictions.parse(JSON.parse(readFileSync(path, "utf8")));
  const map = new Map(output.predictions.map((p) => [p.id, p]));
  if (map.size !== cases.length || map.size !== output.predictions.length)
    throw new Error("Prediction IDs must exactly match evaluation cases");
  const matched = cases.map((c) => {
    const p = map.get(c.id);
    if (!p) throw new Error("Missing prediction: " + c.id);
    return { ...c, ...p };
  });
  return {
    model: output.model,
    kind: output.kind,
    maliciousness: evaluate(
      matched.filter((p) => p.category === "maliciousness"),
    ),
    actor: evaluate(matched.filter((p) => p.category === "actor")),
  };
}
const current = report(currentPath);
const candidate = report(candidatePath);
const result = {
  created_at: new Date().toISOString(),
  mode:
    currentPath === candidatePath
      ? "fixture-self-check"
      : "classifier-comparison",
  notice:
    "Fixture results verify evaluation calculations, not Clef accuracy or real-world calibration. Supply measured predictions from both classifiers for a release comparison.",
  current,
  candidate,
  regression: {
    maliciousness_brier:
      (candidate.maliciousness.brier_score ?? 0) -
      (current.maliciousness.brier_score ?? 0),
    actor_brier:
      (candidate.actor.brier_score ?? 0) - (current.actor.brier_score ?? 0),
  },
};
mkdirSync("artifacts", { recursive: true });
writeFileSync("artifacts/evaluation.json", JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
if (
  result.regression.maliciousness_brier > 0.02 ||
  result.regression.actor_brier > 0.02
)
  process.exitCode = 1;
