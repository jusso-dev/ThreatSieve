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


if __name__ == "__main__":
    unittest.main()
