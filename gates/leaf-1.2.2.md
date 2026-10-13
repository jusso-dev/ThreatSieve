# Gates: leaf 1.2.2 — Priority queue decomposition & enrichment backlog (finding 5, P1)

Scope: separate threat severity, evidence confidence, customer relevance and
operational urgency; route insufficient evidence to an enrichment backlog; rank
the actionable queue by asset impact, exposure, freshness, exploitation,
confidence and review state.

Contract: PLAN.md "Shared interfaces" §5 (operationalUrgency() in
packages/enterprise/src/urgency.ts, four labelled values, enrichment backlog).
File ownership row 1.2.2. Reference failure: synthetic .invalid domain with zero
evidence ranked above a KEV vulnerability because relevance 5% > 1%; "High"
badge conflicting with "Low" customer relevance.

- [x] G1: packages/enterprise/src/urgency.ts exports operationalUrgency() with the pinned component breakdown; repository priority query ranks by it (not json_extract customer.relevance).
  CHECK: sh -c 'rg -n "export function operationalUrgency" packages/enterprise/src/urgency.ts && rg -n "urgency" packages/database/src/repository.ts | head -4'
  EXPECT: /export function operationalUrgency/
  EVIDENCE: 429:        // leaf-1.2.2: the urgency key is COMPUTED, so the keyset boundary is | 430:        // resolved inside SQL — against the cursor row's own urgency value —

- [x] G2: Regression test for the audit case: zero-evidence synthetic .invalid domain never outranks a KEV vulnerability in the priority queue; the zero-evidence item lands in the enrichment backlog instead.
  CHECK: pnpm exec vitest run tests/priority-queue.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  18:48:44 | Duration  3.04s (tests 88%, import 8%, transform 4%)

- [x] G3: Enrichment backlog is a first-class surface: assessments with zero evidence are excluded from the priority queue and listed separately (API summary field + operations.tsx section).
  CHECK: sh -c 'rg -n "Enrichment backlog|enrichment_backlog|enrichmentBacklog" apps/web/components/operations.tsx packages/database/src/repository.ts | head -6'
  EXPECT: /enrich|Enrichment/
  EVIDENCE: apps/web/components/operations.tsx:455:                  Enrichment backlog{" "} | apps/web/components/operations.tsx:465:                aria-label="Enrichment backlog"

- [x] G4: Four separately labelled values (threat severity / evidence confidence / customer relevance / operational urgency) on priority cards and in the table; the severity-vs-relevance badge contradiction is impossible (each badge carries its own label).
  CHECK: sh -c 'rg -n "Evidence confidence|Customer relevance|Operational urgency|Threat severity" apps/web/components/operations.tsx | head -8'
  EXPECT: /Operational urgency/
  EVIDENCE: 430:                    Evidence confidence ·{" "} | 434:                    Customer relevance ·{" "}

- [x] G5: Urgency components use freshness (leaf 1.1.2 FreshnessState), KEV exploitation (vulnerabilities.kev) and review state; test asserts each component moves the score in the expected direction.
  CHECK: pnpm exec vitest run tests/priority-queue.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Start at  18:48:48 | Duration  2.96s (tests 90%, import 6%, transform 3%)

- [x] G6: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: > tsc --noEmit | TYPECHECK_OK

- [x] G7: Expert re-read done: "insufficient evidence" never scores as low threat — it scores as unknown and routes to enrichment; unknown is presented as unknown, not 0.
  EVIDENCE: Re-read as a threat-intelligence domain expert. (1) Scoring: a zero-evidence assessment gets evidenceConfidence/freshness/exploitation = UNKNOWN, each contributing the documented neutral midpoint 0.5 — never 0 (urgency.ts URGENCY_UNKNOWN + docs; test "insufficient evidence is UNKNOWN, never low threat": asserts components === 0.5 and that a fully-known worst case scores LOWER, so unknown cannot masquerade as benign/low). (2) Routing: zero-evidence items are excluded from every urgency-ranked surface (assessmentSummary.priority + sort=relevance listing) and listed in enrichment_backlog with recommended action "enrich" (effectiveRecommendations, read-only; asserted in test). (3) Presentation: operations.tsx renders "Unknown" for evidence confidence, customer relevance and operational urgency on unsupported items (urgencyDisplay returns "Unknown" when evidenceConfidence is unknown) — percent() is never applied to an unknown; partial inputs render "(partial)" with a tooltip listing the neutral-treated unknowns (urgencyDetail). (4) scoreDossier (read model) already keeps threat/confidence/relevance value null when unknown — untouched. (5) The audited conflation is structurally gone: threat severity / evidence confidence / customer relevance / operational urgency are four separately labelled values on cards and in the table, so a "High" severity badge and a "Low" relevance number can no longer contradict each other on one unlabelled row.
