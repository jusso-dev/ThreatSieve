"""Offline regression checks for fail-closed TAXII author exclusions."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import re
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / 'infra/opencti/taxii-reader.py'


class TaxiiAuthorExclusions(unittest.TestCase):
    def provision(self, identities):
        documents = []

        def response(request, **kwargs):
            body = json.loads(request.data)
            documents.append(body)
            document = body['query']
            if 'identities(' in document:
                name = body['variables']['s']
                nodes = [{'id': identities[name], 'name': name}] if name in identities else []
                result = {'identities': {'edges': [{'node': node} for node in nodes]}}
            elif 'capabilities(' in document:
                result = {'capabilities': {'edges': [{'node': {'name': name, 'id': name}} for name in (
                    'KNOWLEDGE', 'TAXIIAPI', 'APIACCESS_USETOKEN'
                )]}}
            elif 'markingDefinitions(' in document:
                result = {'markingDefinitions': {'edges': []}}
            elif 'search:' in document:
                kind = re.search(r'\b(\w+)\(search:', document).group(1)
                result = {kind: {'edges': []}}
            elif 'userAdminTokenAdd(' in document:
                result = {'userAdminTokenAdd': {'plaintext_token': 'test-reader-token', 'expires_at': 'later'}}
            elif 'relationAdd(' in document:
                result = {}
            else:
                operation = document.split(' { ')[1].split('(')[0]
                result = {operation: {'id': operation + '-id', 'name': operation}}
            return io.BytesIO(json.dumps({'data': result}).encode())

        with patch('sys.argv', [str(SCRIPT), 'ap-southeast-2', 'test-secret', 'http://127.0.0.1:8080']), \
                patch('subprocess.check_output', return_value=json.dumps({'OPENCTI_ADMIN_TOKEN': 'test-token'})), \
                patch('subprocess.run') as write_secret, \
                patch('urllib.request.urlopen', side_effect=response), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                runpy.run_path(str(SCRIPT))
            except RuntimeError:
                self.assertTrue(all('mutation' not in entry['query'] for entry in documents))
                write_secret.assert_not_called()
                raise
            write_secret.assert_called_once()
        return documents

    def test_missing_author_stops_before_provisioning(self):
        for identities in ({}, {'admin': 'admin-id'}, {'ThreatSieve connector': 'connector-id'}):
            with self.subTest(identities=identities), self.assertRaisesRegex(RuntimeError, 'Missing author identities:'):
                self.provision(identities)

    def test_all_authors_are_excluded(self):
        documents = self.provision({'ThreatSieve connector': 'connector-id', 'admin': 'admin-id'})
        collection = next(entry for entry in documents if 'taxiiCollectionAdd(' in entry['query'])
        self.assertEqual(json.loads(collection['variables']['i']['filters'])['filters'], [{
            'key': ['createdBy'], 'values': ['connector-id', 'admin-id'],
            'operator': 'not_eq', 'mode': 'and'
        }])
