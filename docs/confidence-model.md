# Confidence model

Confidence is a policy calculation with visible factors. It is distinct from Clef's raw probability of maliciousness.

Source independence uses one shared policy across classifier confidence, dossier
scores and canonical views. Provider-local record IDs are scoped by provider;
explicit `sourceRecordNamespace` identifies shared upstream records and
`originalSourceId` identifies a producer behind a redistributor. Connected groups
collapse configured provider groups, shared original producers and declared
mirrors, so redistribution cannot increase corroboration. Disabled tenant sources
are excluded from canonical assertion counts. Recognised CVE and ATT&CK external
IDs remain global; other external IDs are scoped by their source namespace.
Decision version `decisions-v1.1.2` invalidates cached confidence from the previous
independence policy. Thresholds and weights are unchanged.

## Definitions

Every number shown in the UI is one of the quantities below. They are not interchangeable: a model probability, a composite confidence, a model self-assessment and a heuristic weight sum answer different questions.

| Quantity | Range | What it is | What it is not | Source |
| -------- | ----: | ---------- | -------------- | ------ |
| Malicious probability | 0–1 | The classifier's model output for "is this malicious" (Clef `noul` answer). Uncalibrated model probability; classification thresholds and the human-review gate are applied on top of it. | Not a verdict, not calibrated, not an analyst decision. | `packages/clef/src/index.ts` → `Assessment.malicious.probability` |
| Overall confidence | 0–1 | Composite policy score: Σ(factor value × factor weight), clamped to [0,1]. Factor codes and weights are listed under [Factor weights](#factor-weights). Summarises how well supported the assessment is. | Not a probability; "87% overall confidence" does not mean "87% likely correct". | `packages/scoring/src/index.ts` `scoreConfidence` |
| Evidence strength | 0–1 | The classifier's self-reported evidence-strength expected score divided by 4 — a model self-assessment of evidence quality, carried into confidence as the `EVIDENCE_STRENGTH` factor. | Not overall confidence (older UI copy labelled the composite "Evidence strength"; that label was wrong and is corrected), not a probability of maliciousness, not a source count. | `packages/clef/src/index.ts` (`evidenceStrength` question) |
| Customer relevance | 0–1 | `0.2 × malicious probability + 0.3 × technology match + 0.3 × internal observation + 0.2 × exposed matching assets + 0.2 × (KEV ∧ technology match)`, clamped to 1. | Not a probability the customer will be impacted. | `packages/scoring/src/index.ts` `customerRelevance` |
| Operational urgency | 0–1 | Weighted sum of six components — assetImpact (0.20), exposure (0.15), freshness (0.15), exploitation/KEV (0.25), evidenceConfidence (0.15), reviewState (0.10). Unknown components contribute the neutral midpoint 0.5 and are listed as unknown. | Not threat severity and not customer relevance; unknown is never rendered as 0. | `packages/enterprise/src/urgency.ts` `operationalUrgency`, `URGENCY_WEIGHTS` |
| Heuristic dossier scores (threat / confidence / relevance) | 0–100 | `dossier-v1` heuristic weight sums, clamped 0–100 (see [Dossier scoring](#dossier-scoring-dossier-v1)). Rendered in the UI with a "/100 heuristic" qualifier. | **Not calibrated probabilities** — inspectable policy heuristics only. | `packages/enterprise/src/scoring.ts` `scoreDossier` |

Role probability and human-review probability are model outputs (0–1), like malicious probability. ATT&CK mapping and actor association probabilities are also model outputs; similarity is not attribution.

## Factor weights

Confidence factors are built in `packages/scoring/src/index.ts` `scoreConfidence`. Each factor's code names what the factor measures.

| Factor | Emitted code(s) | Weight |
| ---------------------------------------------- | -------------------------------------------- | -----: |
| Mean evidence confidence × source reliability  | `EVIDENCE_RELIABILITY` (`LOW_EVIDENCE` when none) |   0.35 |
| Independent source groups, capped at three     | `MULTI_SOURCE_CONFIRMATION` (≥2 groups) / `SINGLE_SOURCE_SUPPORT` (1 group) / `LOW_EVIDENCE` (none) |   0.15 |
| Clef evidence-strength expected score / 4      | `EVIDENCE_STRENGTH` |   0.20 |
| Classifier decisiveness, max(p, 1−p)           | `CLASSIFIER_DECISIVENESS` |   0.20 |
| Direct telemetry, sandbox or analyst evidence  | `DIRECT_EVIDENCE` |   0.10 |
| Fraction of evidence older than 30 days        | `STALE_INTELLIGENCE` |  −0.20 |
| Conflicting malicious/benign source assertions | `CONFLICTING_SOURCES` |  −0.25 |
| Shared infrastructure                          | `SHARED_INFRASTRUCTURE` |  −0.30 |
| Truncated evidence bundle                      | `TRUNCATED_EVIDENCE` |  −0.20 |
| No evidence                                    | `LOW_EVIDENCE` |  −1.00 |

`MULTI_SOURCE_CONFIRMATION` is emitted only when at least two independent source groups support the assessment. A single independent group gets `SINGLE_SOURCE_SUPPORT`; no source at all is `LOW_EVIDENCE` and never "confirmation".

Sum weighted factors and clamp to [0,1]. Each factor exposes its input, weight and evidence references. This model is intentionally conservative and uncalibrated until evaluation data supports tuning.

### Factor code history

Codes are a schema union (`ReasonCode` in `packages/schemas/src/index.ts`); renamed codes remain in the union so assessments recorded before the rename stay valid and readable. Earlier names and their true meanings:

- `MULTI_SOURCE_CONFIRMATION` on the evidence-reliability factor → `EVIDENCE_RELIABILITY`. The old code claimed multi-source confirmation for any assessment that had evidence, including single-source ones; that was wrong. The code survives only with its true meaning (≥2 independent groups).
- `LOW_EVIDENCE` on the evidence-strength factor → `EVIDENCE_STRENGTH`; on the classifier-decisiveness factor → `CLASSIFIER_DECISIVENESS`. The old name described neither.
- `CUSTOMER_OBSERVED` on the direct-evidence factor → `DIRECT_EVIDENCE`. `CUSTOMER_OBSERVED` remains in use for the distinct customer-observation reason (`customerContext.observed`).
- `LOW_EVIDENCE` on the truncation penalty → `TRUNCATED_EVIDENCE`.
- `SINGLE_SOURCE_ONLY` → `SINGLE_SOURCE_SUPPORT`. `SINGLE_SOURCE_ONLY` is retained in the union for historical rows only.

ThreatFox, URLhaus and Feodo belong to the same `abuse.ch` independence group. Three mirrors do not count as three independent sources. Unknown providers start with conservative reliability. Source-supplied confidence is retained, not silently promoted to verified truth.

Customer relevance is a separate structured calculation: 0.2 × maliciousness probability, +0.3 technology match, +0.3 internal observation, +0.2 exposed matching assets, +0.2 for KEV combined with a technology match. Clamp to one. Priorities: critical ≥0.85, high ≥0.60, medium ≥0.30, low otherwise. Reasons are fixed codes from matched fields; no generated explanation is required.

Recommendations are derived from policy gates. High-confidence supported malicious findings can recommend block/hunt, uncertain cases investigate/enrich, and a KEV plus technology match recommends patch. No recommendation executes a firewall, endpoint or infrastructure action.

## Dossier scoring (`dossier-v1`)

The canonical dossier separates four values from the underlying Clef probabilities. Threat contributions include explicit malicious source assertions (+25), C2 evidence (+20), malware relationships (+15), independent malicious corroboration (+15), recent malicious evidence (+10), KEV (+35), conflicting assertions (−20), shared infrastructure (−40) and effective analyst classification. A sighting alone leaves threat **unknown**.

Confidence combines evidence confidence weighted by source reliability (up to 55), independent source groups (up to 20), recent evidence (up to 15), direct tenant observations (+10) and conflicts (−25). Admiralty reliability weights are policy values A=.95, B=.80, C=.65, D=.40, E=.20, F=.50; F means unjudged, not unreliable. Information credibility is displayed separately.

Relevance uses explicit customer observations (+40), exact technology/product matches (+30), industry targeting (+15), country targeting (+10), KEV plus technology exposure (+25), monitored organisation/brand/domain/person targeting (+30), critical-asset sightings (+20) and region targeting (+10). Scores are clamped to 0–100. Each contribution links to evidence IDs. Missing context remains unknown. Priority is 50% threat + 35% relevance + 15% confidence, with thresholds 80/60/30 for critical/high/medium. These are inspectable policy heuristics, not statistically calibrated probabilities.

## Evaluation status

**The current evaluation set is synthetic, small and UNCALIBRATED. Production calibration is outstanding.** No accuracy, precision or calibration claim may be made from it.

What exists today: ten synthetic challenge cases (six binary maliciousness, three bounded actor cases and one deliberately unlabelled insufficient-evidence case; nine carry stipulated labels) — see the model-quality row in [readiness.md](readiness.md). The suite is generated by `scripts/evaluation-challenges.ts` as an evaluation dataset of kind `synthetic-challenge` and measured end-to-end by `scripts/evaluate-live.ts`. It probes robustness and decision-gate behaviour (escalation, unknown-not-benign, no invented ATT&CK or actor). It does **not** measure real-world accuracy, population precision/recall, or calibration.

Dataset kinds are enforced by `packages/scoring/src/dataset.ts`:

- `synthetic-challenge` — stipulated labels on synthetic cases. Every such dataset carries a `caveat` field; when the producer omits one the schema fills the canonical refusal text so a parsed synthetic dataset can never reach a report uncaveated. *(Runner gate requirement, outstanding: evaluation runners must refuse to print bare headline accuracy for a `synthetic-challenge` dataset without an explicit producer caveat, and must always print the caveat beside any metrics.)*
- `analyst-labelled` — independent human truth. Must include reviewer, rationale, label timestamp and evidence links (schema-enforced in `EvaluationCase`).

### Plan before any accuracy or calibration claim

1. **Independently labelled evaluation set.** Build an `analyst-labelled` dataset of representative production cases, labelled by analysts who did not author the model's assessment, held out from all prompt/threshold/weight tuning. Report FP/FN counts alongside case counts — never a bare percentage from a handful of cases.
2. **Calibration.** With the labelled set, measure Brier score and binned calibration error (`packages/scoring/src/evaluation.ts` `evaluate`), inspect reliability bins, and calibrate thresholds on a development split only. Until this is done every probability in the UI is an uncalibrated model output.
3. **False-positive / false-negative analysis.** At the operating threshold, review every FP and FN case individually (confusion matrix and FP/FN rates come from `evaluate`), track the human-escalation rate, and budget false negatives (missed threats) and false positives (analyst workload) as separate costs.
4. **Model-change regression gates.** Any change to classifier model, prompt, question set, score weights or thresholds must pass before release:
   - `pnpm eval` (`scripts/evaluate.ts`) — fixture self-check and recorded-baseline comparison; exits non-zero on a Brier regression greater than 0.02.
   - `pnpm exec tsx scripts/evaluation-challenges.ts` — regenerate the synthetic-challenge dataset.
   - `pnpm exec tsx scripts/evaluate-live.ts <private-dataset> --live` — measured run of both Clef models (at most 200 paid calls) against a dataset. Synthetic-challenge runs must retain their caveat, and the decision gates (human review, unknown-not-benign, no unsupported mappings) must not regress.
   Release is gated on no significant degradation in precision, recall, false-positive rate, false-negative rate and Brier score on the analyst-labelled set, plus the synthetic robustness suite still passing. Until the analyst-labelled set exists, the synthetic suite is the only gate and no quality claim may leave the repository.
