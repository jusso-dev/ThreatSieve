# Recovery verification

Production backups contain private intelligence and authentication records. Keep SQL exports and raw payloads outside Git, owner-readable only, on encrypted storage. Never attach an export or Wrangler log containing a presigned download URL to an issue or CI artifact.

## Cloudflare drill, 7 October 2026

The production database was exported after recording a D1 Time Travel bookmark. The 311,193,850-byte SQL export was restored into both local SQLite and a newly provisioned, isolated D1 database. No Worker or queue was bound to the recovery database.

- Local restore: 239.53 seconds. SQLite integrity check: `ok`; foreign-key violations: zero.
- Remote D1 import: 375,709 statements; reported SQL execution time 48.63 seconds. This is database execution time, not end-to-end RTO.
- Remote quick check: `ok`; foreign-key violations: zero. Counts matched the exported snapshot across entities, evidence, assessments, tenants, jobs and audit records.
- The temporary remote database was deleted after verification. Production was not restored or modified by the drill.
- A 53,835,637-byte archived MITRE payload was downloaded, uploaded to an isolated recovery prefix, downloaded again and compared byte-for-byte using SHA-256. Checksums matched. The copy/read-back cycle took 11.08 seconds; the recovery copy was removed. The original archive object was untouched.

These prove restore mechanics for this snapshot and payload. They do not establish a contractual recovery objective or prove that every archived object is recoverable. Repeat after schema/storage changes and test representative private payloads using an approved recovery environment.

## Repeatable procedure

1. Record `wrangler d1 time-travel info` using the production configuration, then `wrangler d1 export DB --remote --output <private-file>` with that configuration. Export can briefly block database requests; schedule it appropriately.
2. Create a uniquely named recovery database. Write a separate ignored Wrangler configuration containing only that database binding. Confirm that its ID differs from production.
3. Import the export using `wrangler d1 execute DB --remote --file <private-file> --config <recovery-config>`. Never use the production config for this command.
4. Compare counts against a local SQLite import of the same backup, not a moving production database. Run `PRAGMA foreign_key_check` and `PRAGMA quick_check` remotely and `PRAGMA integrity_check` locally. Run each count as a separate SELECT; D1 limits compound SELECT terms.
5. Read back representative records and verify provenance, assessment distributions, membership and job state without logging private values. Do not dispatch restored outbox jobs.
6. For R2, restore representative archived bytes to a unique `recovery-drills/` prefix and compare SHA-256 hashes. Do not overwrite original keys.
7. Delete only the recovery database and copied objects created by this drill. Retain a sanitized verification report; manage the private backup under your backup policy.

## OpenCTI

Daily encrypted EBS snapshots are configured separately from Cloudflare. Snapshot existence is not a successful restore test. The first application-consistent restore drill completed on 7 October 2026.

### Verified OpenCTI drill

- Gracefully stopped the connector, import worker and platform before refreshing Elasticsearch and stopping the remaining services/Docker. A five-minute systemd watchdog provided a restart safeguard if the operator connection failed. The full quiesce/snapshot-request/healthy-restart sequence took 62 seconds; this was a maintenance interruption, not a zero-downtime backup.
- Created an encrypted snapshot of the quiesced data volume. Production resumed after snapshot acceptance; the drill waited for snapshot completion before restoring it.
- Booted a clean Amazon Linux recovery host with a separate SSM-only instance profile, no Secrets Manager access, no public address and a new security group with zero ingress. On-demand capacity was unavailable at the account quota, so this disposable host used Spot capacity. No production/EKS capacity was replaced or resized.
- Attached the snapshot-derived disk as a **secondary data disk**, never as the recovery host's boot disk. Original systemd services, SSM state and connector containers were not started from it.
- Compared all 521 persisted files (71,014,557 bytes) across Elasticsearch, Redis, RabbitMQ and object-storage volumes using SHA-256 before starting restored services. Every file matched.
- Removed original container and network runtime state on the **copy only**. Reused the recovered local images and volumes with [recovery_config.py](../infra/opencti/recovery_config.py). This constructs exactly five services with an internal-only network, no published ports, no import worker or external connectors, and independent recovery administrator/health credentials. It preserves the data encryption key and RabbitMQ node hostname required to read the stored data.
- Verified identical document counts across all 14 Elasticsearch indexes (1,482 documents) before starting the recovered application. All five dependency/platform health checks passed. Recovery volume creation through healthy application startup took 128.8 seconds; this excludes host provisioning, snapshot completion and subsequent acceptance checks and is **not** a contractual end-to-end RTO.
- Read back the expected real vulnerability, malware and ATT&CK technique through authenticated OpenCTI GraphQL; verified the malware-to-technique `uses` relationship and six assessment Notes. RabbitMQ reported 20 healthy queues and zero queued messages. A request from the recovered application to the production ThreatSieve API was blocked by network isolation.
- Terminated the temporary host and removed its root/data volumes, snapshot, security group, instance profile and IAM role after acceptance. The production host, production data volume, normal backup policy, blakSOC EKS resources and its private ingress rule were preserved. Final production containers and host monitoring were healthy.

The private command/state reports remain in ignored, owner-readable operator artifacts. This test verifies the captured database/object/broker state and application read-back. Because the snapshot contained no queued messages, it does not establish replay behavior for a nonempty RabbitMQ backlog. It also does not test full regional loss, a different OpenCTI version, or a contractual RPO/RTO.

### Repeat safely

1. Coordinate a brief write-quiescence window with every consumer of the shared OpenCTI host, including blakSOC. Confirm production identity, current host health, backup policy, disk space and access rules. Do not run provisioning/update scripts against a shared instance just to perform a restore test.
2. Create a clean, separately tagged recovery host with SSM-only access and a private security group. Keep a private journal of every resource created. Never reuse the production instance profile or production security group for the restored workload.
3. Resolve Compose configuration **on the production host into root-only storage**. Generate a sanitized recovery document using `recovery_config(source, rabbit_hostname)` from the helper. Do not print resolved configuration, copy it into Git or send it to CloudWatch logs. The helper deliberately omits workers/connectors, host mounts, published ports and privileged/host networking settings; it rejects unexpected volume identities.
4. Install an independent restart watchdog, gracefully stop writers and dependencies, record Elasticsearch counts, hash persisted volume files and flush filesystem writes. Request an encrypted EBS snapshot, then always restart production in a `finally`/failure handler and verify health. Do not leave production paused while waiting for snapshot completion. Cancel the watchdog only after a healthy restart.
5. Wait for snapshot completion. Restore it into a newly tagged volume in the recovery host's AZ and attach it as a secondary disk. Identify the disk by its exact EBS volume serial before mounting; reject any mismatch. For XFS copies use `nouuid`. Never boot the unsanitized production disk.
6. With recovery Docker stopped, verify the saved file manifest. On the **clone only**, quarantine original Docker container/network state before mounting its Docker data directory for the clean daemon. Start only the sanitized internal-network dependencies from existing images, verify index counts, then start the isolated platform. No connector/import worker may run during the drill.
7. Verify known STIX identities, relationships, Notes, object storage, broker health and blocked external egress. Use independent recovery credentials; never render production connector keys into a restored container. Record which queues/objects were actually tested and avoid extending the claim to untested cases.
8. Save a sanitized report. Confirm each temporary resource's exact ID and ownership tag before terminating/deleting it. Verify the temporary root/data disks, snapshot, security group, role/profile and active Spot request are gone. Final production checks are read-only; preserve other agents' resources and changes.

This follows AWS's guidance to [pause writes for consistent EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html) and Docker's [internal network isolation](https://docs.docker.com/reference/compose-file/networks/#internal). Recovery snapshots contain credentials and private intelligence even when the running recovery configuration is sanitized; treat the entire snapshot as sensitive.
