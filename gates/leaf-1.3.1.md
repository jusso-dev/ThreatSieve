# Gates: leaf 1.3.1 — Canonical entities & source assertions (finding 6, P2)

Scope: canonical entities with source assertions underneath; reversible alias
resolution; latest assessment per observable by default with expandable
history; source lineage preserved so mirrors never imply independent
corroboration.

Contract: PLAN.md "Shared interfaces" §7 (packages/database/src/canonical.ts,
migration 0025 entity_aliases, mirrored flag). File ownership row 1.3.1.
Reference failures: the same MITRE campaign listed separately via MITRE, TAXII
and MISP; the same CVE occupying two priority slots through different
assessments.

- [x] G1: packages/database/src/canonical.ts exports the canonical lookup + latestAssessmentPerObservable(); migrations/0025_canonical_aliases.sql creates reversible entity_aliases and applies cleanly (pnpm db:validate).
  CHECK: sh -c 'rg -n "export function" packages/database/src/canonical.ts | head -4 && pnpm db:validate >/dev/null 2>&1 && echo DB_OK'
  EXPECT: DB_OK
  EVIDENCE: 0025 creates `canonical_aliases(tenant_id,canonical_id,alias_id,basis,created_at)` — NOT a rename of 0001 `entity_aliases` (that table remains name-lookup text aliases for Repository.sourceStatements/resolveAlias). Exports: annotateMirroredAssertions (packages/database/src/canonical.ts:43), resolveCanonicalId (:83), aliasEntity (:97), unaliasEntity (:147), canonicalEntities (:205), latestAssessmentPerObservable (:310). CHECK → `43:export function annotateMirroredAssertions(` + `DB_OK`.

- [x] G2: Regression test: one campaign ingested via three sources (MITRE direct, TAXII mirror, MISP mirror) resolves to one canonical entity with three source assertions; mirrors sharing an upstream record id are flagged mirrored:true and are not counted as independent corroboration.
  CHECK: pnpm exec vitest run tests/canonical.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: `Test Files  1 passed (1)` / `Tests  7 passed (7)`. Case: "three separately stored campaigns sharing upstream collapse at read-time…" — three `putEntity` rows (camp-mitre/taxii/misp), shared sourceRecordId+externalId, no attachSource onto one id, no aliasEntity before assert. `identityGroup` + `browseCanonicalEntities` → one canonical (lowest id), source_count=3, mirror_count=2, independent_corroboration_count=1.

- [x] G3: Regression test: one CVE assessed twice resolves to one canonical slot in listings/priority with assessment_count and expandable history; alias resolution is reversible (un-alias restores the separate views).
  CHECK: pnpm exec vitest run tests/canonical.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: Same run `Tests  7 passed (7)`. Cases: CVE twice → one latest slot assessment_count=2 + history; "latestAssessmentPerObservable honors status filters on the deduped set" (status=pending excludes confirmed-latest obs-filter-a; status=confirmed keeps it with count 2) — route passes AssessmentFilters into the function before flat branch; "alias resolution is reversible" (explicit aliasEntity wins over lowest-id; unaliasEntity restores separate browse rows when no shared externalId/sourceRecordId).

- [x] G4: UI: intelligence library/detail show the canonical entity by default with source lineage underneath ("seen via N sources; M mirrors") and expandable per-assessment history including revision reasons.
  CHECK: sh -c 'rg -n "canonical|mirror|history" apps/web/components/intelligence-library.tsx apps/web/components/intelligence-detail.tsx | head -8'
  EXPECT: /canonical|mirror/
  EVIDENCE: library `canonical_id` / `mirror_count` / `Canonical · seen via {n} sources; {m} mirrors` (intelligence-library.tsx ~185); detail `canonical_id`, `mirrored`, `?history=1`, `seen via … mirrors`, expandable assessment history with `revision reason` (intelligence-detail.tsx:12–46,58–59). IntelligenceCard composed unchanged.

- [x] G5: Typecheck clean and db:validate green.
  CHECK: sh -c 'pnpm typecheck && pnpm db:validate >/dev/null 2>&1 && echo LEAF131_OK'
  EXPECT: LEAF131_OK
  EVIDENCE: `LEAF131_OK` after root `tsc --noEmit`, tests/system tsc, `@threatsieve/web` tsc, and `pnpm db:validate`.

- [x] G6: Expert re-read done: default views dedupe; history/lineage is never lost (source assertions immutable underneath), and confidence never counts a mirror as an independent second source.
  EVIDENCE: `annotateMirroredAssertions` groups by upstream sourceRecordId; mirrors never increment independent_corroboration_count. Read-time `identityGroup` collapses separate entity rows sharing externalId or sourceRecordId (lowest id; explicit canonical_aliases win) without deleting entity_sources or auto-INSERT aliases. After discovery, members are filtered with `repo.visible(tenantId, id)` — invisible private peers never become canonical_id/member_ids/alias_ids or contribute provenance (test: "tenant A does not see tenant B private campaign…"). Filters on GET /v1/assessments reuse `repo.assessments` so view/sort/cursor/INVALID_CURSOR stay correct; only latest-per-observable rows emit. packages/scoring still keys MULTI_SOURCE_CONFIRMATION off source.independent_group (packages/scoring/src/index.ts:29-65) — unowned; distinct independent_group values can still inflate that factor.
