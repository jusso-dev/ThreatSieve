import type {
  DecisionRequest,
  DecisionTransport,
  Model,
} from "../packages/clef/src/index";
export class RecordedTransport implements DecisionTransport {
  calls: { model: Model; input: DecisionRequest }[] = [];
  constructor(
    private probability = 0.97,
    private role = "c2",
    private review = 0.1,
  ) {}
  async run(model: Model, input: DecisionRequest) {
    this.calls.push({ model, input });
    const answers: Record<string, unknown> = {};
    for (const [id, q] of Object.entries(input.questions)) {
      if (q.type === "noul")
        answers[id] = {
          type: "noul",
          noul:
            id === "malicious"
              ? this.probability
              : id === "humanReview"
                ? this.review
                : id === "actor_unknown"
                  ? 0.9
                  : 0.93,
        };
      if (q.type === "choice") {
        const keys = Object.keys(q.criteria);
        answers[id] = {
          type: "choice",
          choice: this.role,
          confidence: 0.95,
          probabilities: Object.fromEntries(
            keys.map((key) => [
              key,
              key === this.role ? 0.95 : 0.05 / (keys.length - 1),
            ]),
          ),
        };
      }
      if (q.type === "score")
        answers[id] = {
          type: "score",
          score: 3.8,
          confidence: 0.9,
          legend: Object.fromEntries(q.criteria.map((v, i) => [i, v])),
          probabilities: { 0: 0, 1: 0, 2: 0, 3: 0.2, 4: 0.8 },
        };
    }
    return { model, answers, usage: { input_tokens: 500, output_tokens: 0 } };
  }
}
