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
                "scope": os.getenv("CONNECTOR_SCOPE", "indicator,malware,attack-pattern,relationship,note,report,campaign,threat-actor,intrusion-set,infrastructure,vulnerability,observed-data,sighting"),
                "type": "EXTERNAL_IMPORT",
                "log_level": "info",
                "confidence_level": 70,
            },
        })
        self.collections = [value.strip() for value in os.getenv("THREATSIEVE_COLLECTION_IDS", "").split(",") if value.strip()]
        from uuid import UUID
        for value in self.collections:
            UUID(value)
        if len(self.collections) > 20:
            raise ValueError("Configure at most 20 collections per connector")
        self.heartbeat_enabled = os.getenv("THREATSIEVE_HEARTBEAT", "false").lower() == "true"
        self.version = "enterprise-delivery-v2"
        self.session = requests.Session()
        self.session.headers.update({"Authorization": "Bearer " + os.environ["THREATSIEVE_API_KEY"]})

    def get(self, path):
        response = self.session.get(self.url + path, timeout=60, allow_redirects=False, stream=True)
        try:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("ThreatSieve returned an unexpected status")
            data = bytearray()
            for chunk in response.iter_content(65536):
                data.extend(chunk)
                if len(data) > 16 * 1024 * 1024:
                    raise ValueError("ThreatSieve response exceeds 16 MiB")
            return json.loads(data)
        finally:
            response.close()

    def heartbeat(self, status, error_type=None):
        if not self.heartbeat_enabled:
            return
        payload = {"connector_id": self.helper.connect_id, "status": status, "version": self.version}
        if error_type:
            payload["error_type"] = error_type
        response = self.session.post(self.url + "/v1/integrations/opencti/heartbeat", json=payload,
                                     timeout=15, allow_redirects=False)
        try:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("Heartbeat returned an unexpected status")
        finally:
            response.close()

    def poll(self):
        # Monitoring failures never undo a successfully committed delivery cursor.
        status, error_type = "ok", None
        try:
            self.sync()
        except Exception as error:
            status, error_type = "error", type(error).__name__
            self.helper.connector_logger.error("ThreatSieve sync failed", {"error_type": error_type})
        try:
            self.heartbeat(status, error_type)
        except Exception as error:
            self.helper.connector_logger.error("ThreatSieve heartbeat failed", {"error_type": type(error).__name__})

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
            state["export_cursor"] = export["cursor"]
            self.helper.set_state(state)
        self.sync_collections(state)

    def sync_collections(self, state):
        # Collections are explicitly selected by the operator; no customer telemetry is inferred or exported.
        from urllib.parse import urlencode
        from uuid import uuid4
        snapshots = state.setdefault("collection_snapshots", {})
        for collection in self.collections:
            publication = self.get("/v1/collections/" + collection + "/publication")["publication"]
            if not publication or snapshots.get(collection) == publication["published_at"]:
                continue
            next_token = None
            seen_tokens = set()
            while True:
                query = {"limit": 100}
                if next_token:
                    query["next"] = next_token
                page = self.get("/v1/taxii/api/collections/" + collection + "/objects/?" + urlencode(query))
                if page.get("objects"):
                    bundle = {"type": "bundle", "id": "bundle--" + str(uuid4()), "objects": page["objects"]}
                    work_id = self.helper.api.work.initiate_work(self.helper.connect_id, "ThreatSieve collection " + collection)
                    self.helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id, update=True)
                    self.helper.api.work.to_processed(work_id, "ThreatSieve collection page queued")
                if not page.get("more"):
                    break
                next_token = page.get("next")
                if not next_token or next_token in seen_tokens:
                    raise ValueError("TAXII response missing or repeating continuation")
                seen_tokens.add(next_token)
            snapshots[collection] = publication["published_at"]
            self.helper.set_state(state)

    def run(self):
        while True:
            self.poll()
            time.sleep(int(os.getenv("CONNECTOR_INTERVAL_SECONDS", "60")))


if __name__ == "__main__":
    ThreatSieveConnector().run()
