# Open-issue remediation and release evidence

This document separates repository fixes from live acceptance. A green PR does
not prove a deployed feed sync, a recovered checkpoint or calibrated accuracy.

| Issue | Repository work | Remaining acceptance |
| --- | --- | --- |
| #10 | Progress-aware pipeline/outbox alerts, bounded outbox drain and allowlisted probe subjects; tenant-scoped dispatch progress | Protected production release; manual and scheduled health probes, including within two hours of a feed sync |
| #23 | Tenant/root/input-index outcomes and indexed cross-page deduplication; outcome, observable and downstream delivery commit together; 20 rejection samples with complete counts | Apply migrations before deployment; inspect any legacy imports already blocked by oversized messages |
| #24 | Bulk archives contain at most 1,000 inputs per page with 100 processed per continuation (at most ten reads per archive page); new feed fanout pages contain at most 500 records and generate ten-record normalization chunks; deterministic keys survive retries | Monitor archive I/O and sustained workload after release |
| #25 | Explicit original producer and record namespace; provider-local defaults; one conservative independence model across canonical views, classifier and dossier | Review configured producer identities; legacy assertions retain provider-local identity until refreshed |
| #26 | Analyst-labelled datasets require sampling/exclusion documentation and a held-out split; measured reports include source coverage, latency and Wilson intervals | Obtain representative independent analyst labels, run both classifiers, reconcile actual provider cost and assess subgroup/calibration uncertainty before tuning thresholds |
| #27 | Read-only lifecycle inventory and [policy decision record](retention-policy.md); no deletion path | Owner-approved retention, RPO/RTO, holds and archive dependency inventory before bounded cleanup can be implemented |
| #28 | Material versions exclude collection clocks/archive metadata; content, version and downstream work commit atomically; unchanged/reordered inputs skip downstream work | Verify avoided work and event coverage on released feed cycles |
| #29 | Stable sanitized credential/access/rate-limit/network failure categories | Supply credentials, confirm permitted use/redistribution, then prove nonempty and subsequent incremental syncs in both environments |
| #30 | Distinct embedding-provider, invalid-response and vector-index-write categories; replay generation/crash tests | Upgrade staging through the reviewed release sequence, diagnose one controlled retry, then recover the remaining jobs and verify checkpoint/coverage |

## Read-only operational evidence: 16 October 2026

Neither staging nor production has a Worker secret named `THREATFOX_AUTH_KEY`
or `URLHAUS_AUTH_KEY`. Staging has both feeds enabled with status `never-synced`,
no sync timestamp and no checkpoint. Missing configuration is established;
licensing and actual upstream access have not been established. Never place
credential values in issue comments, PRs or logs.

Staging MISP has 29 failed enrichment jobs: 26 malware and three actor records.
The stored category is `Error`, the source is in error, and no successful sync
or checkpoint exists. That historical category cannot prove an AI, index or
context-size cause. New provider-specific categories make a controlled retry
actionable without recording provider bodies or descriptions.

The latest staging migrations are 0027 and 0021; 0022 and 0024–0026 still need
reviewed application, followed by 0028–0032. Do not deploy this application or
replay unfinished jobs against the older schema. Migration 0031 copies source
assertions into a table with a namespace-inclusive primary key and rebuilds its
indexes; verify source-row counts and take a D1 recovery bookmark before release.

A read-only inventory with cutoff 1 October found 493,650 completed jobs,
493,679 delivered outbox rows, 29 unfinished jobs and one active feed lock. None
predated that illustrative cutoff. This cutoff is not an approved retention rule.
No remote database, archive, secret or queue was changed by this remediation.

## Controlled MISP recovery after release

An operator uses the private source-job view to select one failed MISP enrichment,
preserves its generation/error state in private evidence, and submits the existing
`POST /v1/feeds/misp/jobs/:jobId/replay` endpoint with `feeds:write`. It increments
the generation and resets only that job's delivery. Verify its completion,
embedding/index state and downstream work before expanding the replay. Do not
use the broad `--replay-unfinished` repair command for these 29 jobs. Test stale
copies and redelivery against persisted results. A healthy checkpoint requires
all descendants to finish and finalization to advance the source once; then
check expected coverage and a subsequent source sync. Required production
approval remains in the protected release workflow.

Operational ownership is the deploying ThreatSieve operator until an owner is
recorded. The System health view and production probe monitor configured feed
failures/staleness, pipeline stalls and source finalization. Feed credentials and
licensing must be assigned to an owner before claiming restored coverage.
