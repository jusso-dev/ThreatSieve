import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('monitoring', Path(__file__).parents[2] / 'infra/opencti/monitoring.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MonitoringTest(unittest.TestCase):
    def test_existing_alarm_destinations_survive_reconfiguration(self):
        previous = {'AlarmActions': ['arn:aws:sns:ap-southeast-2:123456789012:approved'], 'OKActions': []}
        self.assertEqual(module.notification_actions(None, 'ap-southeast-2', previous)['AlarmActions'], previous['AlarmActions'])

    def test_only_explicit_regional_sns_topics_can_be_added(self):
        topic = 'arn:aws:sns:ap-southeast-2:123456789012:approved'
        result = module.notification_actions(topic, 'ap-southeast-2', {})
        self.assertEqual(result['AlarmActions'], [topic])
        self.assertEqual(result['OKActions'], [topic])
        for invalid in ['arn:aws:automate:ap-southeast-2:ec2:terminate', 'arn:aws:sns:us-east-1:123456789012:wrong-region', 'user@example.com']:
            with self.assertRaises(ValueError):
                module.notification_actions(invalid, 'ap-southeast-2', {})
