#!/usr/bin/env python3
"""Publish bounded, non-sensitive host metrics using the EC2 instance role."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SERVICES = frozenset(('redis', 'elasticsearch', 'minio', 'rabbitmq', 'opencti', 'worker', 'threatsieve'))
NAMESPACE = 'ThreatSieve/OpenCTI'


def containers_healthy(rows):
    services = {row.get('Service'): row for row in rows}
    return int(all(name in services and services[name].get('State') == 'running'
                   and services[name].get('Health', '') in ('', 'healthy') for name in SERVICES))


def memory_percent(text):
    values = {line.split(':', 1)[0]: int(line.split()[1]) for line in text.splitlines() if ':' in line}
    total, available = values['MemTotal'], values['MemAvailable']
    if total <= 0 or not 0 <= available <= total:
        raise ValueError('Invalid memory counters')
    return round((total - available) * 100 / total, 2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', required=True)
    parser.add_argument('--instance-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', args.region) or not re.fullmatch(r'i-[0-9a-f]{17}', args.instance_id):
        raise ValueError('Invalid deployment identifiers')
    compose = ['docker', 'compose', '--project-directory', '/opt/opencti']
    result = subprocess.run(compose + ['ps', '--all', '--format', 'json'], capture_output=True, text=True, timeout=20, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    # The secret remains inside the container environment, never in process arguments or logs.
    check = subprocess.run(compose + ['exec', '-T', 'opencti', 'node', '-e',
        "fetch('http://127.0.0.1:8080/health?health_access_key='+encodeURIComponent(process.env.APP__HEALTH_ACCESS_KEY),{signal:AbortSignal.timeout(10000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"],
        capture_output=True, timeout=20)
    disk = shutil.disk_usage('/opt/opencti')
    values = {
        'ProbeHeartbeat': (1, 'Count'),
        'ContainersHealthy': (containers_healthy(rows), 'Count'),
        'PlatformHealthy': (int(check.returncode == 0), 'Count'),
        'DiskUsedPercent': (round(disk.used * 100 / disk.total, 2), 'Percent'),
        'MemoryUsedPercent': (memory_percent(Path('/proc/meminfo').read_text()), 'Percent'),
    }
    document = {'Namespace': NAMESPACE, 'MetricData': [
        {'MetricName': name, 'Value': value, 'Unit': unit, 'Timestamp': datetime.now(timezone.utc).isoformat(),
         'Dimensions': [{'Name': 'InstanceId', 'Value': args.instance_id}]}
        for name, (value, unit) in values.items()]}
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
        json.dump(document, file)
        file.flush()
        subprocess.run(['aws', '--region', args.region, 'cloudwatch', 'put-metric-data', '--cli-input-json', 'file://' + file.name],
                       capture_output=True, timeout=20, check=True)
    print(json.dumps({'result': 'published', 'metrics': {name: value for name, (value, _) in values.items()}}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print subprocess stderr or health endpoint URLs.
        print(json.dumps({'result': 'failed', 'error_type': type(error).__name__}))
        raise SystemExit(1)
