# OpenCTI integration

`connectors/opencti/connector.py` is an external-import connector using the [supported OpenCTI helper](https://docs.opencti.io/latest/development/connectors/). It registers with OpenCTI and calls `send_stix2_bundle` with a complete STIX 2.1 bundle and work ID. It does not create thousands of entities individually through GraphQL.

```sh
cd connectors/opencti
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python connector.py
```

Supply secrets through the process environment or secret manager:

- `OPENCTI_URL`, `OPENCTI_TOKEN`
- `CONNECTOR_ID` (stable UUID), `CONNECTOR_NAME`, `CONNECTOR_SCOPE`
- `THREATSIEVE_URL`, `THREATSIEVE_API_KEY` with `assessment:read`
- Optional `CONNECTOR_INTERVAL_SECONDS` (default 60)

The connector polls tenant-scoped `/v1/exports`. Export cursors combine creation time and ID, so equal timestamps do not skip exports. State advances only after the helper accepts the complete bundle. Errors leave the cursor unchanged for retry. Credentials are never written into STIX or logs.

STIX includes confidence and ThreatSieve assessment references. Inferred relationships carry `x_threatsieve_assertion_type`, probabilities and evidence IDs. Assessment Notes explicitly distinguish source data from inferred decisions. Redistribution is checked on each evidence record, including records that share a source ID. Non-redistributable evidence, analyst identity and free-text analyst reasons are omitted from exported bundles by default. Customer telemetry is excluded unless an explicitly authorised future export policy permits it.

Deploy the connector in infrastructure that can reach your OpenCTI broker and ThreatSieve HTTPS API. It is a Python integration process, not a Cloudflare Worker, because the OpenCTI helper manages its native connector/broker workflow. A Dockerfile runs it as a non-root user. The connector needs a target-environment acceptance test before production use; offline tests cannot prove connectivity to your OpenCTI deployment.

Analyst feedback produces an immutable export revision with a new cursor, allowing an already-running connector to receive corrected decisions. Redelivering an unchanged revision reuses the same bundle. STIX `modified` advances with the assessment revision. Effective analyst classifications have `assertion_type: analyst_confirmed` and no invented probability; the original classifier result remains explicitly labelled `x_threatsieve_model_classification`. Benign corrections use the custom open-vocabulary indicator type `benign` and the effective classification field. Downstream policies must honor that correction rather than treating the existence of an Indicator as a block instruction. Previously delivered bundles remain historical records; ThreatSieve does not autonomously retract firewall rules.

For the separate private EC2 instance, provisioning, backups and Session Manager access, see [OpenCTI hosting](opencti-hosting.md). The connector dependency is pinned to the deployed platform release; upgrade them together and verify a real STIX bundle import.

## Standalone or OpenCTI front end

ThreatSieve handles collection, prioritisation, evidence-backed assessment and operational analyst intelligence. OpenCTI is an optional broader knowledge graph/system of record. The core workspace does not depend on an OpenCTI deployment.

Set `THREATSIEVE_COLLECTION_IDS` to a comma-separated list of up to 20 explicitly published TAXII collection UUIDs to send additional curated entities, reports and campaign context through the same connector helper. The API key also needs `intel:read`. Collection state advances after all snapshot pages are accepted; failed deliveries retry with stable STIX object identities. Private sightings are deliberately not included without a separate explicit sharing policy. Existing assessment export cursors continue independently.

For connector health monitoring, set `THREATSIEVE_HEARTBEAT=true` and grant the connector's ThreatSieve key `integration:write`. The key does not need `admin` or `ops:read`. Each poll reports success or a sanitized error class; the authenticated workspace owns the heartbeat. See [production operations](operations.md) for thresholds and the distinction between helper acceptance and indexed intelligence. Compose passes the collection and heartbeat settings from the host secret configuration; they default to empty/disabled for compatibility with existing keys.
