#!/usr/bin/env python3
"""Configure host alarms, optionally routing transitions to an approved SNS topic."""
import argparse
import json
import re
import subprocess
import tempfile
import time


def notification_actions(topic, region, existing):
    if topic:
        if not re.fullmatch(r'arn:aws:sns:' + re.escape(region) + r':\d{12}:[A-Za-z0-9_-]{1,256}', topic):
            raise ValueError('Use an SNS topic ARN in the host region')
        return {'AlarmActions': [topic], 'OKActions': [topic], 'InsufficientDataActions': []}
    # Re-running monitoring setup must not silently remove configured paging.
    return {key: existing.get(key, []) for key in ('AlarmActions', 'OKActions', 'InsufficientDataActions')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', required=True)
    parser.add_argument('--instance-id', required=True)
    parser.add_argument('--role', required=True)
    parser.add_argument('--alarm-topic-arn', help='Existing SNS topic with explicitly approved subscribers')
    args = parser.parse_args()
    notification_actions(args.alarm_topic_arn, args.region, {})
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', args.region) or not re.fullmatch(r'i-[0-9a-f]{17}', args.instance_id) or not re.fullmatch(r'[\w+=,.@-]{1,64}', args.role):
        raise ValueError('Invalid AWS identifiers')

    def call(service, operation, document, flag='--cli-input-json', extra=()):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
            json.dump(document, file)
            file.flush()
            result = subprocess.run(['aws', '--region', args.region, service, operation, flag, 'file://' + file.name, *extra, '--output', 'json'], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('AWS operation failed: ' + service + ' ' + operation)
            return json.loads(result.stdout) if result.stdout.strip() else {}

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
    existing = {alarm['AlarmName']: alarm for alarm in call('cloudwatch', 'describe-alarms', {'AlarmNames': [prefix + item[0] for item in alarms]}).get('MetricAlarms', [])}
    for name, threshold, comparison, missing, ns in alarms:
        call('cloudwatch', 'put-metric-alarm', {
            'AlarmName': prefix + name, 'AlarmDescription': 'OpenCTI host health; inspect the host before remediation. No automatic resource actions.',
            'Namespace': ns, 'MetricName': name, 'Dimensions': dimensions,
            'Statistic': 'Minimum' if comparison == 'LessThanThreshold' else 'Maximum',
            'Period': 60, 'EvaluationPeriods': 5, 'DatapointsToAlarm': 3,
            'Threshold': threshold, 'ComparisonOperator': comparison, 'TreatMissingData': missing,
            'ActionsEnabled': True, **notification_actions(args.alarm_topic_arn, args.region, existing.get(prefix + name, {})),
            'Tags': [{'Key': 'Application', 'Value': 'ThreatSieve'}],
        })
        time.sleep(0.4)
    call('cloudwatch', 'put-dashboard', {'DashboardName': 'ThreatSieve-OpenCTI', 'DashboardBody': json.dumps({'widgets': [
        {'type': 'metric', 'x': (i % 2) * 12, 'y': (i // 2) * 6, 'width': 12, 'height': 6,
         'properties': {'title': name, 'region': args.region, 'period': 60,
                        'metrics': [[ns, name, 'InstanceId', args.instance_id]], 'stat': 'Maximum'}}
        for i, (name, _, _, _, ns) in enumerate(alarms)]})})
    print('Configured seven host alarms and dashboard. Notification destinations ' + ('set to the supplied SNS topic.' if args.alarm_topic_arn else 'preserved.'))


if __name__ == '__main__':
    main()
