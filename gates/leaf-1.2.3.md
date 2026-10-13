# Gates: leaf 1.2.3 — Score definitions & factor naming (finding 8, P1)

Scope: explicit score definitions, heuristic scores labelled /100, correct
factor names, and honest evaluation documentation (independent labels,
calibration, FP/FN analysis, regression gates).

Contract: PLAN.md "Shared interfaces" §6 (MULTI_SOURCE_CONFIRMATION semantics,
SINGLE_SOURCE_SUPPORT code, label changes, docs definitions table). File
ownership row 1.2.3. Reference defects: UI mixes malicious probability,
confidence, evidence strength and relevance percentages; a single-source
assessment displays a "multi source confirmation" confidence factor; readiness
register records a tiny synthetic evaluation with production calibration
outstanding.

- [x] G1: MULTI_SOURCE_CONFIRMATION is emitted only with ≥2 independent source groups; single-source assessments get SINGLE_SOURCE_SUPPORT (new code in packages/schemas). Test covers 1-source and 2-independent-source cases.
  CHECK: pnpm exec vitest run tests/scoring-labels.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Test Files  1 passed (1) / Tests  11 passed (11) — includes
  "a single independent source group gets SINGLE_SOURCE_SUPPORT, never
  MULTI_SOURCE_CONFIRMATION", "MULTI_SOURCE_CONFIRMATION requires two
  independent source groups", and the abuse.ch-mirror single-group case.
  scoreConfidence (packages/scoring/src/index.ts:49-67) emits
  MULTI_SOURCE_CONFIRMATION only for groups≥2, SINGLE_SOURCE_SUPPORT for 1,
  LOW_EVIDENCE for 0; the reliability factor is renamed EVIDENCE_RELIABILITY
  so no factor is "named multi-source, computed from reliability".

- [x] G2: UI labels corrected: "Evidence strength" → "Overall confidence"; every heuristic 0–100 score renders with "/100 heuristic"; probability rows state which quantity they show.
  CHECK: sh -c 'rg -n "Overall confidence|/100 heuristic" apps/web/components/investigation.tsx apps/web/components/intelligence-card.tsx | head -6'
  EXPECT: /Overall confidence/
  EVIDENCE: investigation.tsx:354 "Overall confidence" (was "Evidence
  strength"); intelligence-card.tsx:110/118/126/265 render threat, confidence,
  relevance as "N/100 heuristic" in the verdict bar and "Why these scores?"
  panel. Probability rows (investigation.tsx:310-336) carry "Model probability
  (0–1)" per row (malicious, role, human review).

- [x] G3: docs/confidence-model.md contains a definitions table for malicious probability, confidence, evidence strength, customer relevance and operational urgency (with ranges and sources), and states the current evaluation set is synthetic, small and uncalibrated with production calibration outstanding.
  CHECK: sh -c 'rg -n "Definitions|uncalibrated|synthetic" docs/confidence-model.md | head -6'
  EXPECT: /uncalibrated|synthetic/
  EVIDENCE: docs/confidence-model.md:5 "## Definitions" table (malicious
  probability / overall confidence / evidence strength / customer relevance /
  operational urgency / heuristic dossier scores, each with range, definition,
  "what it is not" and source module); :67 "The current evaluation set is
  synthetic, small and UNCALIBRATED. Production calibration is outstanding."

- [x] G4: Evaluation hygiene recorded: dataset kind labels enforced by packages/scoring/src/dataset.ts, and docs describe the FP/FN + calibration + model-change regression gate plan with run commands.
  CHECK: sh -c 'rg -n "synthetic-challenge|analyst-labelled" packages/scoring/src/dataset.ts && rg -n "regression|calibration" docs/confidence-model.md | head -4'
  EXPECT: /synthetic-challenge/
  EVIDENCE: packages/scoring/src/dataset.ts:63 kind enum
  ["synthetic-challenge","analyst-labelled"]; :71-82 transform guarantees every
  parsed synthetic-challenge dataset carries a caveat (canonical refusal text
  SYNTHETIC_CHALLENGE_CAVEAT when the producer omits one), so headline accuracy
  cannot be reported from an uncaveated synthetic dataset. docs
  "### Plan before any accuracy or calibration claim" covers independently
  labelled evaluation set, calibration, FP/FN analysis and model-change
  regression gates with run commands (`pnpm eval`,
  `scripts/evaluation-challenges.ts`, `scripts/evaluate-live.ts <ds> --live`).
  Runner-side hard refusal documented as an outstanding gate requirement in
  docs (evaluate.ts/evaluate-live.ts are outside this leaf's file ownership).

- [x] G5: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: TYPECHECK_OK (tsc --noEmit + tests/system tsconfig + web tsconfig).
  eslint clean on all six touched files. Full unit suite green: 18 files /
  175 tests, including sibling tests/decisions.test.ts,
  tests/analyst-state.test.ts, tests/priority-queue.test.ts.

- [x] G6: Expert re-read done: no label anywhere in this leaf's UI surfaces can be read as a calibrated probability claim where the number is a heuristic weight sum.
  EVIDENCE: reviewed every numeric label in investigation.tsx and
  intelligence-card.tsx. Heuristic weight sums: overall confidence (composite)
  — labelled "overall confidence", with an explicit note "composite policy
  score (weighted factors clamped to 0–1 …), not a calibrated probability"
  (investigation.tsx:357-361); customer relevance — note "heuristic policy
  score (0–1), not a calibrated probability" (investigation.tsx:~478); dossier
  threat/confidence/relevance — all render "/100 heuristic" and the panel
  states "inspectable heuristics, not calibrated probabilities". Quantities
  that are genuine model outputs (malicious, role, human-review, ATT&CK
  mapping, actor association) are labelled model probability or already carry
  "similarity is not attribution"; none of them is a weight sum. Confidence
  factor list shows "value × weight" with codes renamed to what they measure.
  No remaining label on these two surfaces presents a weight sum as a
  calibrated probability.
