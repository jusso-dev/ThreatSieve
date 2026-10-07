#!/usr/bin/env python3
"""Configure host-scoped CloudWatch metrics/alarms. No paging or automated EC2 actions."""
import argparse
import json
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', required=True)
    parser.add_argument('--instance-id', required=True)
    parser.add_argument('--role', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', args.region) or not re.fullmatch(r'i-[0-9a-f]{17}', args.instance_id) or not re.fullmatch(r'[\w+=,.@-]{1,64}', args.role):
        raise ValueError('Invalid AWS identifiers')

    def call(service, operation, document, flag='--cli-input-json', extra=()):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
            json.dump(document, file)
            file.flush()
            result = subprocess.run(['aws', '--region', args.region, service, operation, flag, 'file://' + file.name, *extra], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('AWS operation failed: ' + service + ' ' + operation)

    namespace = 'ThreatSieve/OpenCTI'
    call('iam', 'put-role-policy', {
        'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'cloudwatch:PutMetricData',
        'Resource': '*', 'Condition': {'StringEquals': {'cloudwatch:namespace': namespace}}}]
    }, '--policy-document', ('--role-name', args.role, '--policy-name', 'PublishOpenCTIHealth'))
    dimensions = [{'Name': 'InstanceId', 'Value': args.instance_id}]
    alarms = [
        ('ProbeHeartbeat', 1, 'LessThanThreshold', 'breaching', namespace),
        ('ContainersHealthy', 1, 'LessThanThreshold', 'breaching', namespace),
        ('PlatformHealthy', 1, 'LessThanThreshold', 'breaching', namespace),
        ('DiskUsedPercent', 85, 'GreaterThanThreshold', 'missing', namespace),
        ('MemoryUsedPercent', 90, 'GreaterThanThreshold', 'missing', namespace),
        ('StatusCheckFailed', 0, 'GreaterThanThreshold', 'missing', 'AWS/EC2'),
        ('CPUUtilization', 90, 'GreaterThanThreshold', 'missing', 'AWS/EC2'),
    ]
    prefix = 'threatsieve-opencti-production-'
    for name, threshold, comparison, missing, ns in alarms:
        call('cloudwatch', 'put-metric-alarm', {
            'AlarmName': prefix + name, 'AlarmDescription': 'OpenCTI host health; inspect the host before remediation. No automatic resource actions.',
            'Namespace': ns, 'MetricName': name, 'Dimensions': dimensions,
            'Statistic': 'Minimum' if comparison == 'LessThanThreshold' else 'Maximum',
            'Period': 60, 'EvaluationPeriods': 5, 'DatapointsToAlarm': 3,
            'Threshold': threshold, 'ComparisonOperator': comparison, 'TreatMissingData': missing,
            'ActionsEnabled': True, 'AlarmActions': [], 'OKActions': [], 'InsufficientDataActions': [],
            'Tags': [{'Key': 'Application', 'Value': 'ThreatSieve'}],
        })
        time.sleep(0.4)
    call('cloudwatch', 'put-dashboard', {'DashboardName': 'ThreatSieve-OpenCTI', 'DashboardBody': json.dumps({'widgets': [
        {'type': 'metric', 'x': (i % 2) * 12, 'y': (i // 2) * 6, 'width': 12, 'height': 6,
         'properties': {'title': name, 'region': args.region, 'period': 60,
                        'metrics': [[ns, name, 'InstanceId', args.instance_id]], 'stat': 'Maximum'}}
        for i, (name, _, _, _, ns) in enumerate(alarms)]})})
    print('Configured seven host alarms and the ThreatSieve-OpenCTI dashboard; no notification destinations or automated actions.')


if __name__ == '__main__':
    main()
