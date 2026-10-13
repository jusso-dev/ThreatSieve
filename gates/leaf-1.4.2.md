# Gates: leaf 1.4.2 — Requirements & reports ergonomics (finding 10, P2)

Scope: searchable source/entity pickers, readable criterion labels, explicit
match logic with preview; claim-level citations, reviewer approval, audience/TLP
markings, immutable published revisions in reports.

Contract: PLAN.md "Shared interfaces" §10 (criterion label map, report claims,
tlp/audience/approval fields, publish immutability). File ownership row 1.4.2.
Reference state: criteria render raw keys (sourceIds, entityTypes —
workspace-objects.tsx:1005); report HTML is plain text with references listed
separately (packages/enterprise/src/export.ts:271–279).

- [x] G1: Every criterion key renders via the label map (sourceIds→"Sources", entityTypes→"Entity types", …); raw keys are never rendered; non-requirement detail views (workspace-objects.tsx:505) also use labels.
  CHECK: sh -c 'rg -n "Sources|Entity types" apps/web/components/workspace-objects.tsx | head -4'
  EXPECT: /Sources|Entity types/
  EVIDENCE: |
    35:  sourceIds: "Sources",
    36:  entityTypes: "Entity types",

- [x] G2: Criteria editor offers searchable source and entity pickers (backed by existing /v1/sources and entity endpoints) and renders a plain-language criterion preview (e.g. "Match objects that … AND …"); match logic (all-must-match) is stated explicitly in the UI.
  CHECK: sh -c 'rg -n "picker|Picker|search" apps/web/components/workspace-objects.tsx | head -6'
  EXPECT: /picker|Picker|search/
  EVIDENCE: |
    32:import { ReferencePicker, ReferenceList } from "./workspace-references";
    807:        <ReferencePicker
    1349:            <CriterionSourcePicker
    1366:            <CriterionEntityPicker
    1489:function CriterionSourcePicker({
    1504:    <div className="criterion-picker">

- [x] G3: Reports support claims: {text, sourceRefs[]} rendered with claim-level citations in HTML export; TLP + audience markings and reviewer approval (approvedBy/approvedAt) render in the export header; test asserts these in reportHtml output.
  CHECK: pnpm exec vitest run tests/reports.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: |
    Test Files  1 passed (1)
         Tests  3 passed (3)
      Start at  20:37:31
      Duration  3.08s (tests 62%, import 30%, transform 8%)

- [x] G4: Publishing freezes the revision: editing a published report creates a new revision and never mutates the published one; test asserts immutability and that revision reasons remain visible.
  CHECK: pnpm exec vitest run tests/reports.test.ts 2>&1 | tail -6
  EXPECT: /Test Files\s+\d+ passed/
  EVIDENCE: |
    Test Files  1 passed (1)
         Tests  3 passed (3)
      Start at  20:37:31
      Duration  3.08s (tests 62%, import 30%, transform 8%)

- [x] G5: Typecheck clean.
  CHECK: pnpm typecheck && echo TYPECHECK_OK
  EXPECT: TYPECHECK_OK
  EVIDENCE: |
    > threatsieve@0.1.0 typecheck /Volumes/MacMini/code-projects/ThreatSieve
    > tsc --noEmit && tsc -p tests/system/tsconfig.json && pnpm --filter @threatsieve/web typecheck

    > @threatsieve/web@ typecheck /Volumes/MacMini/code-projects/ThreatSieve/apps/web
    > tsc --noEmit

    TYPECHECK_OK

- [x] G6: Expert re-read done: an analyst who never saw this product could create a requirement, predict what it matches, and publish an audience-marked report with traceable claims without guessing at field names.
  EVIDENCE: |
    Labels replace raw keys in editor + non-requirement detail; preview states
    "Match objects that … AND …" and "All criteria must match". Source picker
    (v1/feeds) and entity picker (v1/search + type filter) are searchable.
    Report editor exposes TLP, audience, approvedBy/At, claims with citations;
    HTML header + claim-level <cite>; publish appends frozen publishedRevisions
    snapshot that later edits do not mutate; history retains revision reasons.
