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

STIX includes confidence and ThreatSieve assessment references. Inferred relationships carry `x_threatsieve_assertion_type`, probabilities and evidence IDs. Assessment Notes explicitly distinguish source data from inferred decisions. Non-redistributable evidence is omitted from exported bundles by default. Customer telemetry is excluded unless an explicitly authorised future export policy permits it.

Deploy the connector in infrastructure that can reach your OpenCTI broker and ThreatSieve HTTPS API. It is a Python integration process, not a Cloudflare Worker, because the OpenCTI helper manages its native connector/broker workflow. A Dockerfile runs it as a non-root user. The connector needs a target-environment acceptance test before production use; offline tests cannot prove connectivity to your OpenCTI deployment.
