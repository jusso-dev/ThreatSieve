# Commercial architecture

ThreatSieve sells decisions, not another feed. The initial product is a standalone analyst workspace and versioned API; the same API supports MSSP tenants, SIEM/EDR/SOAR consumers and OpenCTI enrichment.

## Compounding intelligence

Public intelligence adds shared entities and source-backed relationships. Customer telemetry adds private context. Analyst decisions add labelled outcomes without erasing original model decisions. Evidence archives and model provenance permit historical reevaluation. These layers can improve relevance and calibration over time without requiring cross-tenant exposure of observations.

Tenant data always carries tenant scope. Global intelligence and private observation tables are separate. Future shared signals must use opt-in `sharing_allowed` records, suppress small cohorts and expose only aggregate counts. Consent should be revocable, audited and reflected in aggregate rebuilds. Merely sharing a global observable ID does not authorise sharing the customers who observed it.

## Commercial controls

Start with scoped API keys, tenant budgets, usage records by model/day and rate limits. Add plan entitlements, billing, organisation SSO/MFA, retention controls, data residency requirements, regional resource placement and contractual source rights before broad commercial launch. Provision separate databases for customers needing stronger administrative isolation. Public graph sharding and per-tenant assessment databases can evolve independently.

## Deliberate MVP boundaries

- Required feeds and one complete evidence-to-decision workflow precede a large administration surface.
- Enrichment uses existing intelligence and structured customer context; no arbitrary URL fetching, active scanning or sandbox execution.
- Graph candidates are operational without Vectorize. Semantic retrieval only proposes existing entities.
- Clusters describe evidence-linked activity; generic malware overlap does not automatically name a campaign.
- Analyst overrides are tenant overlays and training examples, not global facts.
- Recommendations are exported for a downstream system to approve and execute.
- Optional feed adapters are integration building blocks with explicit configuration, not automatically enabled subscriptions.

No fabricated performance numbers, classifier calibration claims or million-indicator benchmark is implied by the architecture. A production launch requires representative throughput tests, classifier evaluation, provider contracts and operational acceptance in the deployed environment.
