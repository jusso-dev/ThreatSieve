# Production operations

Open **System health** as an administrator, or poll `GET /v1/ops/status` with a dedicated `ops:read` key. Tenant jobs, usage and connector heartbeats are scoped to the authenticated workspace; global feed state is shared. This endpoint never returns another tenant's telemetry or connector identity.

The five-minute maintenance schedule writes an R2 object and a D1 heartbeat after completing maintenance. The page refreshes every minute while visible. A failed heartbeat cannot silently refresh the success timestamp.

| Signal                              | Threshold                         | Response                                                                             |
| ----------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------ |
| Scheduler / archive heartbeat       | 15 minutes                        | Inspect Worker exceptions, scheduled events, D1 and R2 availability                  |
| Completed enabled-source sync       | 12 hours                          | Inspect source jobs and upstream availability                                        |
| Required feed missing configuration | Warning                           | Configure the provider secret; no successful ingestion is implied                    |
| Failed pipeline jobs                | Any                               | Diagnose safe error category, then explicitly replay                                 |
| Queued or running work              | 15 minutes since original enqueue | Check throughput and leases; distinguish intentional backlog from a stopped consumer |
| Unpublished outbox work             | 10 minutes                        | Check queue producer errors and reservation leases                                   |
| Classification allowance            | 80% of daily assessment attempts  | Review demand and limit; this is not a currency bill                                 |
| Registered OpenCTI connector        | Error or no poll in 10 minutes    | Inspect connector and destination; helper acceptance does not prove indexing         |

An unregistered connector is explicitly unverified. Optional sources that are disabled are not reported as failed services. Credential warnings do not fail the external probe; critical conditions do.

## External probe

`.github/workflows/production-health.yml` probes API liveness, database readiness and operational thresholds every 15 minutes and on manual dispatch. Configure `THREATSIEVE_PRODUCTION_API_ORIGIN`, secret `THREATSIEVE_MONITOR_KEY` (only `ops:read`) and `ENABLE_PRODUCTION_MONITORING=true`. The script prints only fixed endpoint names, validated alert codes and warning counts. Do not upload authenticated response bodies as artifacts in this public repository. GitHub's existing workflow notification settings control delivery; no new email or webhook recipient is configured by ThreatSieve.

Scheduled GitHub workflows can be delayed and are not an uptime SLA. For contractual paging, run the same probe from your monitoring provider and configure an explicitly approved notification destination. Rotate/revoke the monitoring key independently of analyst and connector credentials.

## Delivery recovery

Outbox publishers atomically reserve at most 100 records before publishing queue batches. Reservations expire after five minutes. Acceptance followed by a publisher crash may redeliver a message; deterministic jobs and generation checks tolerate that at-least-once delivery. Consumers preflight bounded message batches against persisted job generations; completed, superseded and actively leased copies are acknowledged without repeated database writes. Duplicate deliveries acknowledge without consuming the active execution's retry budget. Maintenance recovers expired execution leases, up to six executions, then leaves the job failed for review.

Late dead-letter messages cannot overwrite committed results or a newer replay generation. A completed parent may publish a downstream job only for its current generation. Source finalization atomically updates its checkpoint and counters once.

For the specific legacy delivery defect, first take a D1 Time Travel bookmark, then inspect:

```sh
pnpm exec tsx scripts/recover-pipeline.ts --remote
```

`--apply` restores only global jobs that already have a committed result. `--apply --replay-unfinished` additionally requeues failed global jobs and global queued jobs unchanged for at least an hour, increments their generation, and resets their outbox delivery. It never marks unfinished work successful. Both operations create audit entries and private local recovery records. This is an operator repair, not an automatic recurring retry loop. Tenant work and active running jobs are excluded. Prefer the scoped per-job replay API for ordinary failures.

Inspect source record rejection details before retrying poison inputs. Do not purge queues or discard an archive merely to clear an alert. A source becomes healthy only after its descendant processing completes. Validate a subsequent sync for deterministic deduplication.

## OpenCTI heartbeat

Set `THREATSIEVE_HEARTBEAT=true` with a connector key carrying `integration:write`, in addition to `assessment:read` and `intel:read` if collections are configured. Successful and failed polls POST a server-timestamped heartbeat. Error reports contain the exception class only. A monitoring outage does not roll back an accepted delivery cursor. Failed delivery does not advance the cursor. Verify destination indexing separately through OpenCTI before claiming end-to-end delivery.


## Release validation (2026-10-06)

The release passed 93 unit/integration cases, 85 isolated full-stack browser cases, 8 Playwright regression cases and 9 offline OpenCTI connector cases. The tests include concurrent publishers, late dead letters, generation fencing, expired leases, one-time source finalization, tenant isolation and heartbeat scope boundaries. Production accepted real CISA KEV and Feodo-backed assessments using Clef escalation, without unsupported ATT&CK or actor assertions. Source backfill completion and updated OpenCTI host delivery must be verified independently; a green offline suite is not proof of either.
