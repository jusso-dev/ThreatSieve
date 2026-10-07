"""Offline checks for host alarm signals."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('host_health', Path(__file__).resolve().parents[2] / 'infra/opencti/host-health.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class HostSignals(unittest.TestCase):
    def test_all_dependencies_must_be_present_and_running(self):
        rows = [{'Service': name, 'State': 'running', 'Health': 'healthy'} for name in module.SERVICES]
        self.assertEqual(module.containers_healthy(rows), 1)
        self.assertEqual(module.containers_healthy(rows[1:]), 0)
        rows[0]['State'] = 'restarting'
        self.assertEqual(module.containers_healthy(rows), 0)
        rows[0]['State'] = 'running'
        rows[0]['Health'] = 'unhealthy'
        self.assertEqual(module.containers_healthy(rows), 0)

    def test_memory_uses_available_including_reclaimable_cache(self):
        self.assertEqual(module.memory_percent('MemTotal: 1000 kB\nMemAvailable: 600 kB\nMemFree: 100 kB'), 40)
        with self.assertRaises(ValueError):
            module.memory_percent('MemTotal: 0 kB\nMemAvailable: 0 kB')
