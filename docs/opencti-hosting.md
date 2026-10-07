# Private OpenCTI on EC2

ThreatSieve runs on Cloudflare. OpenCTI and its native Python connector run separately on an EC2 host in AWS. The versioned deployment files are under `infra/opencti/`; the platform, worker and `pycti` client are aligned to `7.261002.0`.

The host uses Amazon Linux 2023, `r8i.xlarge` (4 vCPU, 32 GiB RAM), and a retained, encrypted 250 GiB gp3 root volume. Docker volumes persist Elasticsearch, Redis, RabbitMQ and S3-compatible object data there. It has termination protection, IMDSv2, an instance profile scoped to its configuration secret and SSM, no public IP and no ingress rules. Application containers do not receive AWS instance credentials. The selected private subnet must have outbound NAT access to image registries, AWS APIs and the ThreatSieve HTTPS API.

Only OpenCTI's HTTP endpoint is published, on the host loopback address. Databases, object storage and the broker have no host ports. Access OpenCTI through the encrypted SSM tunnel; choose a hostname, trusted HTTPS gateway and access policy before making it public.

## Provision

Requirements: AWS CLI v2 with an authenticated deployment role, Python 3, a private subnet with outbound access, and an existing ThreatSieve tenant. Create an API key through `POST /v1/api-keys` with `assessment:read` only and store the response plus the API origin in an owner-readable JSON file:

```json
{ "key": "<one-time connector key>", "url": "https://your-api.workers.dev" }
```

Do not commit that file. Provisioning generates independent random OpenCTI and dependency credentials in Secrets Manager. User data includes application files and a secret ARN; it contains no passwords or API keys.

```sh
python3 infra/opencti/provision.py ap-southeast-2 VPC_ID PRIVATE_SUBNET_ID \
  admin@example.com artifacts/opencti-key.local.json
python3 infra/opencti/backups.py ap-southeast-2
```

The script records identifiers in ignored `artifacts/opencti-deployment.local.json`. Re-running it detects the existing instance rather than creating another. It is a creation tool, not a rolling upgrade mechanism. It refuses a reused security group with ingress rules. The API key and administrative bootstrap key are separate. Pass `--update-template` to publish a corrected launch-template version without creating or replacing a host. This does not apply updates to the running instance.

## Access and operate

Install the [AWS Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/install-plugin-macos-overview.html), then use the instance ID from the deployment artifact:

```sh
aws ssm start-session --region ap-southeast-2 --target INSTANCE_ID \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["8080"]}'
```

Open `http://localhost:8080`. Retrieve the administrator email and password from the AWS Secrets Manager console, secret `threatsieve-opencti-production/configuration`. Do not paste that secret into logs or issue comments. The console login does not require exposing a public HTTP port.

For maintenance, start a regular SSM session and use:

```sh
sudo systemctl status opencti
sudo journalctl -u opencti --since '10 minutes ago'
cd /opt/opencti
sudo docker compose ps
sudo docker compose logs --tail 50 threatsieve
```

`opencti.service` starts the stack at boot and waits for dependency and application health. Docker restarts failed containers. Logs rotate locally. Secrets are rendered to a root-only `.env`; protect EBS snapshots as credentials-bearing backups. OpenCTI's worker uses the bootstrap platform token. The deployed ThreatSieve connector uses a separate service account in OpenCTI's built-in `Connectors` group, without the Administrator role. Its token expires after 365 days; the exact expiry is stored as `OPENCTI_CONNECTOR_TOKEN_EXPIRES_AT` in Secrets Manager. Rotate it before expiry.

For a fresh installation, run `python3 infra/opencti/service-account.py REGION SECRET_ARN http://localhost:8080` through an active SSM port-forward after initial startup. It creates the service account and saves its token without printing it. On the host, re-run `sudo bash /opt/opencti/bootstrap.sh REGION SECRET_ARN` to refresh the root-only configuration, then `sudo docker compose up -d threatsieve` from `/opt/opencti`. The initial bootstrap falls back to the administrator token only until this step is completed.

The snapshot policy runs daily at 16:00 UTC and keeps seven snapshots of volumes tagged `ThreatSieveBackup=OpenCTI`. These are crash-consistent EBS snapshots, not a tested application-level disaster recovery guarantee. Before major upgrades, stop the stack, take a snapshot, restart it, and validate restore on a separate host. Restore drills and Elasticsearch-native backups are required before treating this single-host integration as highly available. Snapshot encryption follows the source volume. Deleting the instance is prevented until termination protection is explicitly disabled; the volume is retained even after termination.

## Update safely

Pin new platform, worker and pycti versions together, validate Compose, take a recoverable backup and run the STIX round-trip acceptance check. Updating a launch template alone does not change the running instance. Upload reviewed files using SSM, rebuild the connector and restart through systemd. Never mount the Docker socket into application containers or open broker/database ports to the internet.

## Verified deployment

On 2026-10-06, OpenCTI returned HTTP 200 with all dependency health checks passing. The ThreatSieve connector registered and delivered a real CISA KEV assessment bundle; OpenCTI contained the corresponding `CVE-2025-49113` vulnerability and linked assessment Note. The live environment uses real classifier results and source data, with no synthetic demo seed.

## Connector-only maintenance and host monitoring

Use the existing AWS login and deployment artifact to update this host without reprovisioning OpenCTI:

```sh
python3 infra/opencti/monitoring.py \
  --region ap-southeast-2 --instance-id INSTANCE_ID \
  --role threatsieve-opencti-production-host
python3 infra/opencti/update.py --deployment artifacts/opencti-deployment.local.json
```

Configure `THREATSIEVE_COLLECTION_IDS` and `THREATSIEVE_HEARTBEAT=true` in the existing Secrets Manager configuration first. The ThreatSieve key needs `assessment:read`, `intel:read` for collections, and `integration:write` for heartbeats. It does not need administrator access. The updater requires the dedicated OpenCTI connector token; it refuses the bootstrap administrator token. It renders secrets only on the host, retains the previous connector image and root-only files under `/opt/opencti/releases/`, validates Compose, rebuilds and recreates only the connector, and installs a systemd health timer. Review its SSM command result before declaring success. A submitted command is not a completed rollout.

The health probe runs once a minute and publishes five metrics in `ThreatSieve/OpenCTI`, scoped by `InstanceId`: probe heartbeat, required-container health, OpenCTI health, disk utilization and memory utilization. The instance role gains only `cloudwatch:PutMetricData` constrained to that namespace. The `ThreatSieve-OpenCTI` CloudWatch dashboard combines these with native EC2 CPU and status checks. Seven alarms evaluate three breaching minutes out of five; health signals treat missing data as a breach. Disk and memory thresholds are 85% and 90%, respectively. No SNS recipients, webhooks or automated stop/reboot actions are configured. These are visible CloudWatch alarms, not a claim that an external on-call team has received a page.

Check `systemctl status threatsieve-opencti-health.timer` and `journalctl -u threatsieve-opencti-health.service` for sanitized probe results. Startup can briefly show missing-data alarms while the first measurements arrive. A probe failure reports only its exception class; it never logs a credential or health access URL.

For connector rollback, select the recorded release directory, restore its `connector/` files and `compose.yaml`, refresh `.env` from the **current** Secrets Manager version, and recreate only `threatsieve` using the retained `threatsieve-opencti-rollback:RELEASE` image through a temporary Compose override. Do not restore a revoked API key from an older `.env`. The platform and data volumes are unaffected by connector-only rollback. Keep release directories protected and prune old retained images/files under your credential-retention policy.

On 2026-10-07, the connector-only update was deployed to the existing private instance. A curated collection containing the real CISA `CVE-2025-49113` assessment and MITRE's Mori malware, `T1071.001` technique and source-claimed `uses` relationship passed independent STIX validation and completed a five-object OpenCTI import. Read-back verified destination entities and the relationship. Restart preserved the export checkpoint; republishing the same collection retained the same destination object identities and one `uses` relationship. The old ThreatSieve connector key was revoked after verifying its scoped replacement. The health timer published real host measurements and all seven CloudWatch alarms reached OK. No synthetic intelligence or customer telemetry was used in this acceptance collection.

## Shared-host recovery acceptance — 7 October 2026

The application-consistent isolated restore drill has passed; see [recovery verification](recovery.md). The deployment baseline above describes the original private host. A separate blakSOC agent subsequently added a private EKS-to-OpenCTI ingress rule. The drill preserved that rule and all EKS resources. Treat this as a shared integration host: coordinate future production maintenance with its consumers, and perform recovery verification on separate hosts with their own roles, networks and copied data volumes. Production checks following the snapshot/restart were read-only.
