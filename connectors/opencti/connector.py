"""ThreatSieve external-import connector. STIX bundles travel through the OpenCTI helper."""
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from pycti import OpenCTIConnectorHelper


class ThreatSieveConnector:
    def __init__(self):
        required = ["OPENCTI_URL", "OPENCTI_TOKEN", "CONNECTOR_ID", "THREATSIEVE_URL", "THREATSIEVE_API_KEY"]
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError("Required environment variables: " + ", ".join(missing))
        self.url = os.environ["THREATSIEVE_URL"].rstrip("/")
        parsed = urlparse(self.url)
        if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("THREATSIEVE_URL must use HTTPS")
        self.helper = OpenCTIConnectorHelper({
            "opencti": {"url": os.environ["OPENCTI_URL"], "token": os.environ["OPENCTI_TOKEN"]},
            "connector": {
                "id": os.environ["CONNECTOR_ID"],
                "name": os.getenv("CONNECTOR_NAME", "ThreatSieve"),
                "scope": os.getenv("CONNECTOR_SCOPE", "indicator,malware,attack-pattern,relationship,note"),
                "type": "EXTERNAL_IMPORT",
                "log_level": "info",
                "confidence_level": 70,
            },
        })
        self.session = requests.Session()
        self.session.headers.update({"Authorization": "Bearer " + os.environ["THREATSIEVE_API_KEY"]})

    def get(self, path):
        response = self.session.get(self.url + path, timeout=60, allow_redirects=False, stream=True)
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_content(65536):
            data.extend(chunk)
            if len(data) > 16 * 1024 * 1024:
                raise ValueError("ThreatSieve response exceeds 16 MiB")
        return json.loads(data)

    def sync(self):
        state = self.helper.get_state() or {}
        cursor = state.get("export_cursor", "")
        from urllib.parse import urlencode
        page = self.get("/v1/exports?" + urlencode({"cursor": cursor, "limit": 50}))
        for export in page["data"]:
            bundle = self.get("/v1/exports/" + export["id"])
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "ThreatSieve " + datetime.now(timezone.utc).isoformat()
            )
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id, update=True)
            self.helper.api.work.to_processed(work_id, "ThreatSieve STIX bundle queued")
            # Advance only after the helper has accepted the complete bundle.
            self.helper.set_state({"export_cursor": export["cursor"]})

    def run(self):
        while True:
            try:
                self.sync()
            except Exception as error:
                # Exception text may contain URLs or credentials; log only its class.
                self.helper.connector_logger.error("ThreatSieve sync failed", {"error_type": type(error).__name__})
            time.sleep(int(os.getenv("CONNECTOR_INTERVAL_SECONDS", "60")))


if __name__ == "__main__":
    ThreatSieveConnector().run()
