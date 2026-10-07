import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('recovery_config', Path(__file__).resolve().parents[2] / 'infra/opencti/recovery_config.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecoveryConfigTests(unittest.TestCase):
    def source(self):
        return {'services': {name: {'image': name + ':pinned', 'restart': 'always',
                'ports': ['8080:8080'], 'network_mode': 'host', 'privileged': True,
                'environment': {}, 'volumes': []}
                for name in module.SERVICES | {'worker', 'threatsieve'}},
                'volumes': {name: {'name': 'threatsieve-opencti_' + name} for name in module.VOLUMES}}

    def test_isolates_restored_workload_and_replaces_login(self):
        source = self.source()
        source['services']['opencti']['environment'] = {
            'APP__ADMIN__TOKEN': 'production-token', 'APP__ENCRYPTION_KEY': 'data-key'}
        result = module.recovery_config(source, 'rabbit-original')
        self.assertEqual(set(result['services']), module.SERVICES)
        self.assertTrue(result['networks']['default']['internal'])
        self.assertEqual(result['services']['rabbitmq']['hostname'], 'rabbit-original')
        for service in result['services'].values():
            self.assertNotIn('ports', service)
            self.assertNotIn('privileged', service)
            self.assertNotIn('network_mode', service)
            self.assertEqual(service['pull_policy'], 'never')
            self.assertEqual(service['restart'], 'no')
        env = result['services']['opencti']['environment']
        self.assertNotEqual(env['APP__ADMIN__TOKEN'], 'production-token')
        self.assertEqual(env['APP__ENCRYPTION_KEY'], 'data-key')
        self.assertEqual(source['services']['opencti']['environment']['APP__ADMIN__TOKEN'], 'production-token')

    def test_rejects_secret_injection_and_host_mounts(self):
        for field, value in [('environment', {'THREATSIEVE_API_KEY': 'forbidden'}),
                             ('volumes', [{'type': 'bind', 'source': '/var/run/docker.sock'}])]:
            source = self.source()
            source['services']['opencti'][field] = value
            with self.assertRaises(ValueError):
                module.recovery_config(source, 'rabbit-original')

    def test_rejects_wrong_volumes_or_hostname(self):
        source = self.source()
        source['volumes']['elastic']['name'] = 'unrelated'
        with self.assertRaises(ValueError):
            module.recovery_config(source, 'rabbit-original')
        with self.assertRaises(ValueError):
            module.recovery_config(self.source(), 'shell;payload')
