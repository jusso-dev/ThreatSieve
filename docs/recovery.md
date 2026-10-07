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

Daily encrypted EBS snapshots are configured separately from Cloudflare. Snapshot existence is not a successful restore test. The application-consistent OpenCTI restore drill remains pending renewed AWS authentication. The test must use a private isolated host, disable the ThreatSieve connector and other external connectors before starting restored services, validate Elasticsearch/object storage/RabbitMQ consistency, read back known STIX IDs, and remove the temporary host/volumes afterward. Do not attach the production instance profile, production connector credentials or production queues to a running recovery workload.
