# Confidence model

Confidence is a policy calculation with visible factors. It is distinct from Clef's raw probability of maliciousness.

| Factor | Weight |
| --- | ---: |
| Mean evidence confidence × source reliability | 0.35 |
| Independent source groups, capped at three | 0.15 |
| Clef evidence-strength expected score / 4 | 0.20 |
| Classifier decisiveness, max(p, 1−p) | 0.20 |
| Direct telemetry, sandbox or analyst evidence | 0.10 |
| Fraction of evidence older than 30 days | −0.20 |
| Conflicting malicious/benign source assertions | −0.25 |
| Shared infrastructure | −0.30 |
| Truncated evidence bundle | −0.20 |
| No evidence | −1.00 |

Sum weighted factors and clamp to [0,1]. Each factor exposes its input, weight and evidence references. This model is intentionally conservative and uncalibrated until evaluation data supports tuning.

ThreatFox, URLhaus and Feodo belong to the same `abuse.ch` independence group. Three mirrors do not count as three independent sources. Unknown providers start with conservative reliability. Source-supplied confidence is retained, not silently promoted to verified truth.

Customer relevance is a separate structured calculation: 0.2 × maliciousness probability, +0.3 technology match, +0.3 internal observation, +0.2 exposed matching assets, +0.2 for KEV combined with a technology match. Clamp to one. Priorities: critical ≥0.85, high ≥0.60, medium ≥0.30, low otherwise. Reasons are fixed codes from matched fields; no generated explanation is required.

Recommendations are derived from policy gates. High-confidence supported malicious findings can recommend block/hunt, uncertain cases investigate/enrich, and a KEV plus technology match recommends patch. No recommendation executes a firewall, endpoint or infrastructure action.
