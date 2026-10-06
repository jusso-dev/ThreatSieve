# Private OpenCTI on EC2

ThreatSieve runs on Cloudflare. OpenCTI and its native Python connector run separately on an EC2 host in AWS. The versioned deployment files are under `infra/opencti/`; the platform, worker and `pycti` client are aligned to `7.261002.0`.

The host uses Amazon Linux 2023, `r8i.xlarge` (4 vCPU, 32 GiB RAM), and a retained, encrypted 250 GiB gp3 root volume. Docker volumes persist Elasticsearch, Redis, RabbitMQ and S3-compatible object data there. It has termination protection, IMDSv2, an instance profile scoped to its configuration secret and SSM, no public IP and no ingress rules. Application containers do not receive AWS instance credentials. The selected private subnet must have outbound NAT access to image registries, AWS APIs and the ThreatSieve HTTPS API.

Only OpenCTI's HTTP endpoint is published, on the host loopback address. Databases, object storage and the broker have no host ports. Access OpenCTI through the encrypted SSM tunnel; choose a hostname, trusted HTTPS gateway and access policy before making it public.

## Provision

Requirements: AWS CLI v2 with an authenticated deployment role, Python 3, a private subnet with outbound access, and an existing ThreatSieve tenant. Create an API key through `POST /v1/api-keys` with `assessment:read` only and store the response plus the API origin in an owner-readable JSON file:

```json
{"key":"<one-time connector key>","url":"https://your-api.workers.dev"}
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
