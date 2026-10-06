"""Offline connector delivery tests; no OpenCTI service or credentials required."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch


with patch.dict(sys.modules, {
    "pycti": types.SimpleNamespace(OpenCTIConnectorHelper=Mock()),
    "requests": types.SimpleNamespace(Session=Mock()),
}):
    spec = importlib.util.spec_from_file_location(
        "threatsieve_connector",
        Path(__file__).resolve().parents[2] / "connectors/opencti/connector.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class CollectionDelivery(unittest.TestCase):
    def setUp(self):
        self.connector = module.ThreatSieveConnector.__new__(module.ThreatSieveConnector)
        self.connector.collections = ["collection-1"]
        self.connector.helper = Mock()
        self.connector.helper.connect_id = "connector-1"
        self.connector.helper.api.work.initiate_work.return_value = "work-1"
        self.publication = {"publication": {"published_at": "2026-10-06T00:00:00Z"}}
        self.obj = {"type": "domain-name", "id": "domain-name--test", "value": "demo.example"}

    def test_advances_snapshot_only_after_all_pages_are_accepted(self):
        state = {"export_cursor": "retained"}
        saved = []
        self.connector.helper.set_state.side_effect = lambda value: saved.append(copy.deepcopy(value))
        self.connector.get = Mock(side_effect=[
            self.publication,
            {"objects": [self.obj], "more": True, "next": "opaque+/="},
            {"objects": [self.obj], "more": False},
        ])
        self.connector.sync_collections(state)
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["export_cursor"], "retained")
        self.assertEqual(saved[0]["collection_snapshots"]["collection-1"], self.publication["publication"]["published_at"])
        self.assertIn("next=opaque%2B%2F%3D", self.connector.get.call_args_list[-1].args[0])
        for call in self.connector.helper.send_stix2_bundle.call_args_list:
            self.assertEqual(json.loads(call.args[0])["objects"], [self.obj])
            self.assertTrue(call.kwargs["update"])

    def test_failed_delivery_does_not_advance_snapshot(self):
        state = {"collection_snapshots": {"collection-1": "old"}}
        self.connector.get = Mock(side_effect=[self.publication, {"objects": [self.obj], "more": False}])
        self.connector.helper.send_stix2_bundle.side_effect = RuntimeError("Receiver unavailable")
        with self.assertRaises(RuntimeError):
            self.connector.sync_collections(state)
        self.assertEqual(state["collection_snapshots"]["collection-1"], "old")
        self.connector.helper.set_state.assert_not_called()

    def test_unchanged_snapshot_does_not_redeliver(self):
        self.connector.get = Mock(return_value=self.publication)
        self.connector.sync_collections({"collection_snapshots": {"collection-1": self.publication["publication"]["published_at"]}})
        self.connector.helper.send_stix2_bundle.assert_not_called()

    def test_repeated_continuation_fails_without_advancing(self):
        self.connector.get = Mock(side_effect=[self.publication, {"objects": [], "more": True, "next": "same"}, {"objects": [], "more": True, "next": "same"}])
        with self.assertRaisesRegex(ValueError, "repeating continuation"):
            self.connector.sync_collections({})
        self.connector.helper.set_state.assert_not_called()


class PollHealth(unittest.TestCase):
    def setUp(self):
        self.connector = module.ThreatSieveConnector.__new__(module.ThreatSieveConnector)
        self.connector.helper = Mock()
        self.connector.sync = Mock()
        self.connector.heartbeat = Mock()

    def test_successful_poll_reports_success(self):
        self.connector.poll()
        self.connector.heartbeat.assert_called_once_with("ok", None)

    def test_delivery_failure_reports_only_error_class(self):
        self.connector.sync.side_effect = RuntimeError("sensitive upstream text")
        self.connector.poll()
        self.connector.heartbeat.assert_called_once_with("error", "RuntimeError")
        self.assertNotIn("sensitive", str(self.connector.helper.connector_logger.mock_calls))

    def test_monitoring_failure_does_not_redeliver_or_roll_back_cursor(self):
        self.connector.heartbeat.side_effect = RuntimeError("monitor offline")
        self.connector.poll()
        self.connector.sync.assert_called_once()


class TransportSafety(unittest.TestCase):
    def test_redirect_rejected_and_response_always_closed(self):
        connector = module.ThreatSieveConnector.__new__(module.ThreatSieveConnector)
        connector.url = "https://api.example"
        connector.session = Mock()
        response = connector.session.get.return_value
        response.status_code = 302
        with self.assertRaises(ValueError):
            connector.get("/v1/exports")
        response.close.assert_called_once()
        self.assertFalse(connector.session.get.call_args.kwargs["allow_redirects"])

    def test_restarted_delivery_reuses_object_ids(self):
        case = CollectionDelivery()
        case.setUp()
        connector = case.connector
        connector.get = Mock(side_effect=[case.publication, {"objects": [case.obj], "more": False}, case.publication, {"objects": [case.obj], "more": False}])
        # Simulate crash before cursor persistence. Replayed bundles retain stable object identities.
        connector.sync_collections({})
        connector.sync_collections({})
        calls = connector.helper.send_stix2_bundle.call_args_list
        self.assertEqual(json.loads(calls[0].args[0])["objects"], json.loads(calls[1].args[0])["objects"])


if __name__ == "__main__":
    unittest.main()
