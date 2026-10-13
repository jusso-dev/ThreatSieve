# Gates: leaf 1.3.2 — Customer exposure correctness (finding 7, P1)

Scope: distinguish "known exploited vulnerability" from "your exposed asset";
asset IDs, versions, ownership, criticality, internet exposure, inventory
freshness and SIEM/EDR sightings in the environment profile; missing inventory
displays unknown applicability.

Contract: PLAN.md "Shared interfaces" §8 (EnvironmentSchema.assets, wording
contract). File ownership row 1.3.2. Reference failure: empty environment
profile yet CVE cards say "Exploited vulnerability exposure" (hardcoded at
apps/web/components/operations.tsx:363); environment form is comma-separated
names only.

- [x] G1: EnvironmentSchema accepts assets[] with id/name/product/version/vendor/criticality/internetExposed/owner/inventoryFreshness/lastSeenAt; PUT /v1/environment persists and returns them; existing comma-string fields still accepted (backward compatible).
  CHECK: sh -c 'rg -n "assets" packages/schemas/src/index.ts | head -4 && pnpm exec vitest run tests/exposure.test.ts 2>&1 | tail -6'
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: |
    205:  assets: z
    224:export type EnvironmentAsset = CustomerEnvironment["assets"][number];

     Test Files  1 passed (1)
          Tests  6 passed (6)
       Start at  20:12:34
       Duration  2.81s (tests 72%, import 17%, transform 10%)

- [x] G2: Regression test for the audit case: empty profile + KEV CVE → no surface claims customer exposure; wording distinguishes "known exploited vulnerability" from "your exposed asset"; applicability renders "unknown"; relevance is null/unknown (not 0%).
  CHECK: pnpm exec vitest run tests/exposure.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: |
     Test Files  1 passed (1)
          Tests  6 passed (6)
       Start at  20:12:37
       Duration  2.54s (tests 67%, import 20%, transform 13%)

- [x] G3: With assets present, exposure claims are grounded: matching uses product/version applicability, shows matched asset IDs and inventory freshness, and a stale inventory (>90d) yields an "inventory may be out of date" caveat instead of a confident claim.
  CHECK: pnpm exec vitest run tests/exposure.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: |
     Test Files  1 passed (1)
          Tests  6 passed (6)
       Start at  20:12:37
       Duration  2.54s (tests 67%, import 20%, transform 13%)
    (tests cover exact product/version match + asset ids + freshness, substring non-match for "edge"/"ledger", version mismatch rejection, stale >90d caveat, SIEM/EDR sighting distinct from KEV/asset inventory)

- [x] G4: Inventory UI supports repeatable asset rows (id, product, version, criticality, internet exposure, owner) instead of comma-separated names only; CVE card title/copy follows the wording contract (operations.tsx).
  CHECK: sh -c 'rg -n "internetExposed|criticality" apps/web/app/inventory/page.tsx | head -4 && rg -n "unknown|known exploited|Known exploited" apps/web/components/operations.tsx | head -4'
  EXPECT: /criticality|internetExposed/
  EVIDENCE: |
    57:  criticality: EnvironmentAsset["criticality"];
    58:  internetExposed: boolean;
    67:    criticality: "medium",
    68:    internetExposed: false,
    61:// unknown, not zero, and routes to the enrichment backlog.
    108:  if (claim.applicability === "unknown")
    109:    return "Applicability to your environment unknown";
    117:  const { urgency, unknownComponents } = operationalUrgency(a);
    (also operations.tsx:479 "Known exploited vulnerability · Applicability to your environment unknown"; old title "Exploited vulnerability exposure" removed)

- [x] G5: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: |
    > threatsieve@0.1.0 typecheck /Volumes/MacMini/code-projects/ThreatSieve
    > tsc --noEmit && tsc -p tests/system/tsconfig.json && pnpm --filter @threatsieve/web typecheck

    > @threatsieve/web@ typecheck /Volumes/MacMini/code-projects/ThreatSieve/apps/web
    > tsc --noEmit

    TYPECHECK_OK

- [x] G6: Expert re-read done: every exposure sentence on every surface is traceable to a matched asset or says unknown; SIEM/EDR sightings (customer_observations) are surfaced as evidence of exposure where present.
  EVIDENCE: |
    Pass 2–3 re-read (2026-10-13):
    - Empty inventory → evaluateCustomerExposure applicability "unknown", relevance null; UI relevanceDisplay/exposureRelevanceLabel → "Unknown" (never 0%); CVE title via cvePriorityTitle → "Known exploited vulnerability" (not "Exploited vulnerability exposure"); meta → "Applicability to your environment unknown".
    - Matched assets → wording lists asset ids + inventoryFreshness; stale inventoryFreshness/lastSeenAt >90d → "inventory may be out of date" caveat; no substring product matches; version mismatch ≠ match.
    - Observations passed into evaluateCustomerExposure → "SIEM/EDR sighting recorded" distinct from KEV and asset-inventory match; operations exposureMetaLine uses same distinction when a.customer.observed.
    - GET/PUT /v1/environment parse EnvironmentSchema (assets default []); no migration (JSON in customer_environments.data).
    - Refused: no edits to repository.ts, canonical.ts, 0025, assessments GET; no commit.
