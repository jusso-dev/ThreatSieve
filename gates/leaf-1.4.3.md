# Gates: leaf 1.4.3 — Production readiness register & downstream handoffs (finding 11, P1)

Scope: code-side completeness where possible; honest registration of ops-only
acceptance items; downstream handoff design (case ownership, remediation, SLAs
belong to OpenCTI/SIEM/ITSM via visible handoffs + acknowledgements).

Contract: PLAN.md "Scope boundary" and §11. File ownership row 1.4.3 (docs
only). Reference state: live health degraded (ThreatFox/URLhaus unconfigured),
account MFA disabled, readiness register (docs/readiness.md:5) lists SSO, alert
delivery, retention, sustained load, customer acceptance as outstanding.

- [x] G1: docs/readiness.md register updated: rows for this remediation's outcomes (publication policy, freshness/expiry, cluster timestamps, analyst state, queue/urgency, canonical identity, exposure honesty, score definitions, workflow diagnostics) each with implemented-verified evidence (file:line or test name) and remaining acceptance where applicable.
  CHECK: sh -c 'rg -n "Publication|freshness|expir|urgency|canonical|exposure" docs/readiness.md | head -10'
  EXPECT: /Publication|freshness|urgency/
  EVIDENCE: 24:| Customer exposure      | Empty profile → applicability unknown, relevance null, title "Known exploited vulnerability". KEV is not presented as "your exposed asset". Evidence: `packages/enterprise

- [x] G2: Open ops items are explicit, with owners/dates placeholders — ThreatFox/URLhaus secrets + licensing, production MFA enforcement, SSO IdP, alert destination + delivery test, RPO/RTO + retention commitments, sustained load testing, customer integration acceptance. Each is listed as remaining acceptance, never claimed as done.
  CHECK: sh -c 'rg -n "MFA|SSO|ThreatFox|URLhaus|RPO|retention|load|acceptance" docs/readiness.md | head -10'
  EXPECT: /MFA|SSO/
  EVIDENCE: 24:| Customer exposure      | Empty profile → applicability unknown, relevance null, title "Known exploited vulnerability". KEV is not presented as "your exposed asset". Evidence: `packages/enterprise

- [x] G3: docs/intelligence-operations.md gains a downstream-handoff section: ThreatSieve stays the intelligence-decision system; case ownership, remediation, SLAs and outcome feedback flow through OpenCTI/SIEM/ITSM with visible handoff + acknowledgement states; notes that local UI scope (cases/automations/sightings present on this branch) needs explicit product design for those handoffs.
  CHECK: sh -c 'rg -n "handoff|Handoff|acknowledg" docs/intelligence-operations.md | head -6'
  EXPECT: /handoff|Handoff|acknowledg/
  EVIDENCE: 68:7. **Downstream action** — handoff into OpenCTI, SIEM or ITSM for case ownership, containment and SLA clocks. A downstream action happens in the receiving system; ThreatSieve records what was publi

- [x] G4: The audit's "production workflow" chain (requirements → collection → canonical evidence → relevance → analyst judgment → controlled publication → downstream action → outcome feedback) is mapped to concrete product surfaces in docs, with the gaps this remediation closed and the ones that remain.
  CHECK: sh -c 'rg -n "controlled publication|outcome feedback|downstream action" docs/intelligence-operations.md | head -4'
  EXPECT: /downstream action|outcome feedback/
  EVIDENCE: 68:7. **Downstream action** — handoff into OpenCTI, SIEM or ITSM for case ownership, containment and SLA clocks. A downstream action happens in the receiving system; ThreatSieve records what was publi

- [x] G5: Ops-only gates cannot be completed in this session (no IdP access, no feed-secret deployment, no customer environment). They are recorded as ABANDON lines below with reasons, and surfaced in the final report.
  EVIDENCE: ABANDON ids recorded — G5-ThreatFox, G5-MFA, G5-SSO, G5-Alert, G5-RPO, G5-Load, G5-Customer (ops actions outside this repo; no IdP, feed-secret deploy, or customer environment in session)

ABANDON: G5-ThreatFox ThreatFox/URLhaus Worker secrets and feed licensing require secret deploy and commercial agreement outside this repo
ABANDON: G5-MFA production MFA enforcement is an IdP action outside this repo
ABANDON: G5-SSO SSO IdP configuration is an identity-provider action outside this repo
ABANDON: G5-Alert alert destination approval and delivery test require an approved live destination outside this repo
ABANDON: G5-RPO contractual RPO/RTO and retention commitments are contractual/ops actions outside this repo
ABANDON: G5-Load sustained load testing requires a production-like environment and budget outside this session
ABANDON: G5-Customer customer integration acceptance requires a customer environment and destination outside this repo
