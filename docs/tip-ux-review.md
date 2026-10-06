# ThreatSieve analyst experience review

Reviewed 6 October 2026 against ThreatSieve and the [awesome-threat-intelligence catalogue](https://github.com/hslatman/awesome-threat-intelligence/tree/e506c8415406d6d6ad16040c19c23ddb9ed654ac).

## Scope and evidence

The current catalogue contains **244 named entries**: 89 sources, 43 frameworks/platforms, 75 tools, 9 formats and 28 research/standards resources. Every entry was inventoried and assessed for relevance. Primary text was retrieved for 184 entries; 57 requests were unavailable and 3 documents/resources were metadata-only. [The coverage register](research/catalogue.md) and [machine-readable inventory](research/catalogue.json) record each entry and its disposition.

This is an extensive product/workflow review, not a claim to have audited every external project's source code or used every commercial feature. Retrieved landing pages, README files and public documentation were the evidence. Login-only, unavailable and stale references were not treated as verified product capabilities. Current OpenCTI documentation was reviewed separately because its old catalogue URL was unavailable. Links embedded inside external projects were not recursively crawled.

No reference project was installed or executed. ThreatSieve does not import their code. Its only new bundled asset is the self-hosted Geist font with its OFL licence. No new threat feed, commercial subscription, third-party analytics, graph database or model was introduced.

## Decisions drawn from the strongest references

| Primary reference                                                                                              | Relevant workflow                                                                                          | ThreatSieve implementation                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [OpenCTI knowledge overview](https://docs.opencti.io/latest/usage/overview/)                                   | Separate current operations from background knowledge; filter entity lists and pivot through entity pages. | Dedicated intelligence library, typed categories, source filters, alias/external-ID search and entity detail links.                                 |
| [OpenCTI investigation](https://docs.opencti.io/latest/usage/pivoting/)                                        | Relationship exploration provides context for an investigation.                                            | Bounded graph with explicit edge direction, relationship labels and an accessible list representation.                                              |
| [MISP](https://www.misp-project.org/)                                                                          | Correlation and provenance are central to collaborative intelligence.                                      | Each relationship retains its assertion type, source and confidence; ATT&CK evidence links open the cited records.                                  |
| [Yeti](https://yeti-platform.io/)                                                                              | Reusing prior knowledge and pivoting from an artifact reduce repeated investigation work.                  | Persistent triage filters, personal saved views, contextual entity browsing and keyboard lookup.                                                    |
| [Pulsedive](https://pulsedive.com/)                                                                            | Analysts search, filter and pivot across indicators and threats.                                           | Filter combinations run against the server, with stable pagination and confidence/customer-relevance sorting. No model-generated search language.   |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl)                                                        | Modular analysis, connected investigations and analyst feedback.                                           | Preserve the existing provider/API boundaries; make evidence context and analyst actions easier to reach. No migration to another platform runtime. |
| [Cortex](https://github.com/TheHive-Project/Cortex)                                                            | Consolidated individual and bulk observable analysis.                                                      | Preserve asynchronous bulk analysis and explicit job outcomes. Existing analyst decisions and exports remain first-class actions.                   |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)                                                          | Canonical malware identities and synonyms support investigation.                                           | Search and display aliases beside canonical entities. Aliases remain source claims, never invented associations.                                    |
| [MSTICPy](https://github.com/microsoft/msticpy)                                                                | Timelines and entity-centric pivots help analysts connect observations.                                    | Evidence timeline ordered by observation time, with recorded-time fallback explicitly labelled. No inferred events.                                 |
| [Stixview](https://github.com/traut/stixview)                                                                  | Interactive STIX graph controls and entity inspection.                                                     | Local SVG rendering of authenticated API results, depth controls, zoom, node inspector and list mode. No fetching arbitrary graph URLs.             |
| [IOC Fanger](https://github.com/ioc-fang/ioc-fanger)                                                           | Defanging supports safer sharing of indicators.                                                            | Copy-defanged actions replace URL schemes, periods and email separators. Stored intelligence and STIX exports remain canonical.                     |
| [tiq-test](https://github.com/mlsecproject/tiq-test)                                                           | Feed aging and uniqueness are useful quality dimensions.                                                   | Expose real sync timestamps, added/updated counts and errors. Do not fabricate a feed quality score from record volume.                             |
| [MANTIS](https://django-mantis.readthedocs.io/en/latest/)                                                      | Filtering and inspection of original imported objects.                                                     | Progressive disclosure of source metadata and raw fields. Historical UX reference only.                                                             |
| [Hiryu](https://github.com/S03D4-164/Hiryu)                                                                    | Relationship visualisation of intelligence artifacts.                                                      | Preserve meaningful edge semantics while keeping D1. Its older runtime and optional graph infrastructure are not adopted.                           |
| [GOSINT](https://github.com/ciscocsirt/gosint) and [ThreatIngestor](https://github.com/InQuest/ThreatIngestor) | Standardised intake and modular processing.                                                                | Retain the existing normalise/deduplicate/provenance pipeline; browse source contributions without adding arbitrary crawling.                       |

## Repository findings and changes

### Operations: make the queue usable beyond the first page

Before this change, triage offered three views and a transient text filter. The filter icon had no action. The table was newest-first only, filters vanished after navigation, and mobile styling hid search controls.

The queue now supports priority, effective classification, customer observation, observable type, review status and minimum confidence. Analysts can sort newest, oldest, highest confidence or customer relevance. The SQL applies all filters before keyset pagination; sorting never rearranges just the loaded page. An ID tie-breaker prevents repeated rows when scores or timestamps are equal. Malformed cursors and unsupported filter values are rejected.

Filters live in the URL for reload/back navigation and bookmarkable views. Personal saved views persist in D1, scoped to both tenant and user, with a maximum of 50. A matching name updates a saved view. Saves and deletes are audited. Sharing a view link shares filter settings, not permissions or intelligence records.

Summary counts remain workspace-wide, while the table shows the filtered page. Critical/high summary actions open the appropriate attention queue. Filter controls remain present during loading and on mobile. Empty-result messages explain how to recover.

### Intelligence library: make imported knowledge discoverable

Previously, actor, malware, campaign and technique data could be reached through the API or a small search dropdown, but there was no browsable knowledge view.

`/intelligence` now provides categories, canonical names, aliases, external IDs, source filtering, descriptions and cursor pagination. Search uses indexed literal prefix ranges across names, external IDs and aliases. This also avoids D1's short LIKE-pattern limit: full SHA-256 values and long observable searches must work. Category/source filters combine with search. The API returns only global intelligence and observables visible to the authenticated tenant.

The older typed entity-list APIs retain their ID-cursor contract. Their list and detail paths now apply the same visibility checks. No actor similarity is promoted to attribution through browsing.

### Investigation: show the evidence and the relationship

The original graph displayed a root and up to eight neighbouring nodes under a generic arrow, regardless of the actual relationships. The replacement renders the API's real endpoints and direction. Model-inferred edges use dashed styling and explicit text; source-claimed relationships are labelled as claims. Selecting a node shows its source, description and related edges, with a link to continue investigating. A list mode exposes the same edge semantics without relying on graphics.

Limits remain explicit: depth 1–3, at most 100 entities, 200 edges and 30 relationships per visited entity. Truncation is now reported when the per-entity edge limit is reached, not just the global limit. The UI neither fabricates paths nor converts a cluster to a campaign.

Evidence supports text search, source/context filters and a chronological timeline. ATT&CK mappings link to the intelligence record and their supporting evidence. Raw source fields, retrieval time, licence and redistribution status remain inspectable. Unknown attribution remains prominent.

The decision panel now shows the actual classified role and probability; previously it displayed a zero C2 score for every non-C2 role. Defanged clipboard actions report success or clipboard denial. Reassessment disables repeated submission while the request is in flight, checks job progress and links to the new decision without replacing the original record. Returning from an investigation restores the originating queue filters.

### Source operations and navigation

Source rows expand to show added/updated counts, exact sync times, next scheduled sync, licence and the last error. Errors no longer depend on hover-only tooltips. Source name/status filters and a library pivot help trace a feed's contribution.

Global search supports arrow-key selection and Enter to open an existing entity. Enter does not create a new assessment when matching intelligence exists. An explicit assessment action remains available for analysts. Loading and no-results states are visible. The sidebar includes the library and identifies the current page; a keyboard skip link reaches the main content.

### Visual system and responsive behaviour

The existing restrained green/neutral identity is retained. Self-hosted Geist, tabular figures, larger table/evidence text, stronger secondary contrast, consistent filter fields and press/focus feedback improve sustained use. No decorative charts or fabricated KPI values were added. Tables scroll within their panels, long hashes wrap appropriately, graph panning stays inside its canvas, and mobile filters remain accessible. Reduced-motion behaviour remains supported.

## Deliberately deferred

- Full case management, tasks, reports and intelligence requirements: valuable patterns in larger platforms, but need defined lifecycle, permissions, retention and collaboration semantics.
- ATT&CK coverage heatmaps: require an agreed distinction between observed behaviour, detection coverage and candidate similarity. A colourful matrix over candidate data would mislead.
- Feed quality scoring: requires measured freshness, overlap and downstream outcomes, not guessed scores.
- Extra sources: require current endpoint, credential and redistribution validation. A catalogue listing is not an integration contract.
- Autonomous response, sandboxes, arbitrary crawling and chatbot workflows: outside ThreatSieve's defined responsibility.
- Dark theme: requires a complete contrast review of semantic colours, graphs, forms and notifications; this release focuses on a coherent, tested light workspace.

## Verification

Regression coverage includes browser workflows against real local Workers/D1 bindings, all sort modes and tie-breaking, saved-view persistence and isolation, private observable visibility, long hashes/search terms, literal wildcard handling, alias/source filtering, graph/evidence controls, keyboard lookup, source details and mobile overflow. Existing classification, tenant, authentication, bulk, export and team tests remain in the suite.

Release verification passed 58 unit/integration tests, 74 tester-army/e2e tests and 8 Playwright regressions. Type checking, lint, repository security checks, production dependency audit and the evaluation fixture self-check also passed. Those evaluation fixtures are not a measurement of live classifier accuracy. The release also corrects the staging workflow to use `pnpm run deploy`, avoiding pnpm's unrelated built-in `deploy` command.

Screenshots in the README are captured from the labelled synthetic environment. They are not evidence of live threat activity or model performance. External services are not called by unit or browser tests.
