# Classification

The wrapper uses the [official Clef typed decision API](https://developers.cloudflare.com/ai/models/%40cf/cloudflare/clef-flash/): `model`, `state` and `questions`, with `noul`, `choice` and `score`. It does not parse generated prose. The transport implements `env.AI.run('@cf/cloudflare/clef-flash', input)` and escalates to `@cf/cloudflare/clef`.

Candidate generation traverses known provenance-bearing graph relationships up to three levels with hard fan-out limits. Optional Vectorize retrieval can add existing ATT&CK/actor entities; results are rehydrated from D1, so an unknown vector ID is never a new fact. The embedding model is `@cf/baai/bge-base-en-v1.5`; create a 768-dimension cosine index.

An ATT&CK candidate is asked about only when it has supporting evidence marked behavioural. Generic malicious indicators and malware associations cannot, by themselves, produce mappings. Each accepted mapping keeps evidence IDs, model inference status and probability. Defaults: accepted ≥0.90, probable ≥0.70, weak ≥0.50, otherwise omitted. All probabilities remain in the raw decision record, including rejected candidates.

Actor candidates receive independent yes/no questions. Multiple actors can have non-zero similarity. The unknown question is always included. A strong-attribution flag requires at least three independent evidence dimensions and ≥0.95 model support. The UI always describes model outputs as potential associations. Fingerprint weights are frequency/confidence heuristics, not calibrated statistical evidence.

Untrusted descriptions stay in state. Question instructions expressly reject instructions embedded in state. Candidate output keys, answer types, probability bounds and probability sums are validated. Out-of-set answers fail closed. Prompt wording is one defence; candidate restrictions, behavioural gates, shared-infrastructure penalties and analyst review are separate deterministic controls. Prompt injection is not claimed to be mathematically eliminated.

Flash escalates if the combined confidence falls below 0.90 or review probability reaches 0.25. The full model can still produce a review-required outcome. Missing evidence yields unknown even if a model supplies a high maliciousness score. Shared infrastructure cannot become malicious without direct supporting evidence. Conflicting evidence forces review.

`classification_runs` retain model, available model version, schema version, question-set version, evidence version, candidate set, raw response, input tokens and duration. Versions unavailable from Cloudflare are left absent rather than invented. Cache keys include tenant, observable, evidence version, schema/question versions and model. Evidence hashes include the UTC day to reevaluate stale intelligence.

Evaluation separates maliciousness and actor decisions. Metrics: precision, recall, FPR, FNR, Brier score, ten-bin expected calibration error and human escalation rate. A denominator with no applicable cases returns null. Labelled cases include benign infrastructure, C2, phishing, scanners, ambiguous evidence and adversarial report instructions. Offline fixtures exercise the evaluator; actual model releases require saved measured predictions on a representative held-out dataset.
