#!/usr/bin/env python3
"""Roll out the connector and health probe to an existing SSM-managed OpenCTI host.
Secrets stay in Secrets Manager and are rendered only on the host. Platform containers
and data volumes are not recreated. Existing connector files/image are retained for rollback.
"""
import argparse
import base64
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--deployment', default='artifacts/opencti-deployment.local.json')
    args = parser.parse_args()
    state = json.loads(Path(args.deployment).read_text())
    region, instance, secret = state['region'], state['instanceId'], state['secretArn']
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region) or not re.fullmatch(r'i-[0-9a-f]{17}', instance):
        raise ValueError('Invalid host identifiers')
    if not secret.startswith('arn:aws:secretsmanager:' + region + ':'):
        raise ValueError('Secret must be in the host region')
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for source, target in [
            ('infra/opencti/compose.yaml', 'compose.yaml'),
            ('infra/opencti/host-health.py', 'host-health.py'),
            ('connectors/opencti/Dockerfile', 'connector/Dockerfile'),
            ('connectors/opencti/requirements.txt', 'connector/requirements.txt'),
            ('connectors/opencti/connector.py', 'connector/connector.py'),
        ]:
            tar.add(ROOT / source, arcname=target)
    script = '''set -eu
umask 077
cd /opt/opencti
release=$(date -u +%Y%m%dT%H%M%SZ)
backup="/opt/opencti/releases/$release"
mkdir -p "$backup"
cp compose.yaml .env "$backup/"
cp -a connector "$backup/connector"
image=$(docker compose images -q threatsieve)
docker image tag "$image" "threatsieve-opencti-rollback:$release"
base64 -d <<'BUNDLE' | tar -xz -C /opt/opencti
''' + base64.b64encode(archive.getvalue()).decode() + '''
BUNDLE
aws secretsmanager get-secret-value --region ''' + shlex.quote(region) + ' --secret-id ' + shlex.quote(secret) + ''' --query SecretString --output text > /opt/opencti/secret-update.json
trap 'rm -f /opt/opencti/secret-update.json' EXIT
python3 - <<'CONFIG'
import json,pathlib,re
root=pathlib.Path('/opt/opencti')
values=json.loads((root/'secret-update.json').read_text())
if not values.get('OPENCTI_CONNECTOR_TOKEN') or values['OPENCTI_CONNECTOR_TOKEN']==values['OPENCTI_ADMIN_TOKEN']:
    raise ValueError('A dedicated OpenCTI connector token is required')
if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*',k) for k in values):
    raise ValueError('Invalid configuration names')
if any(not isinstance(v,str) or '\\n' in v or '\\r' in v for v in values.values()):
    raise ValueError('Configuration values must be single-line strings')
(root/'.env').write_text('\\n'.join(k+"='"+v.replace("'", "\\\\'")+"'" for k,v in values.items())+'\\n')
(root/'.env').chmod(0o600)
CONFIG
rm -f /opt/opencti/secret-update.json
docker compose config --quiet > "$backup/config-check.log" 2>&1
docker compose build threatsieve > "$backup/build.log" 2>&1
docker compose up -d --no-deps --wait --wait-timeout 120 threatsieve > "$backup/restart.log" 2>&1
cat > /etc/systemd/system/threatsieve-opencti-health.service <<'UNIT'
[Unit]
Description=ThreatSieve OpenCTI host health metrics
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/opencti/host-health.py --region ''' + region + ' --instance-id ' + instance + '''
TimeoutStartSec=75
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
UNIT
cat > /etc/systemd/system/threatsieve-opencti-health.timer <<'UNIT'
[Unit]
Description=Monitor OpenCTI health every minute
[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=5s
Unit=threatsieve-opencti-health.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now threatsieve-opencti-health.timer
systemctl start threatsieve-opencti-health.service
printf 'Connector updated; rollback files and image retained for release %s\\n' "$release"
'''
    command = {
        'InstanceIds': [instance], 'DocumentName': 'AWS-RunShellScript',
        'Comment': 'Update ThreatSieve connector and host health monitoring',
        'Parameters': {'commands': [script], 'executionTimeout': ['900']},
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
        json.dump(command, file)
        file.flush()
        result = subprocess.run(['aws', '--region', region, 'ssm', 'send-command', '--cli-input-json', 'file://' + file.name, '--output', 'json'], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('SSM update submission failed')
    command_id = json.loads(result.stdout)['Command']['CommandId']
    print('SSM update command: ' + command_id, flush=True)
    for _ in range(10):
        time.sleep(3)
        response = subprocess.run(['aws', '--region', region, 'ssm', 'get-command-invocation', '--command-id', command_id, '--instance-id', instance, '--output', 'json'], capture_output=True, text=True)
        if response.returncode:
            continue
        status = json.loads(response.stdout)
        if status['Status'] not in ('Pending', 'InProgress', 'Delayed'):
            print('Update status: ' + status['Status'])
            print(status.get('StandardOutputContent', ''))
            if status['Status'] != 'Success':
                raise RuntimeError('Inspect protected host release logs; no secrets are printed by this script')
            return
    print('Update continues on the host; inspect command status before acceptance.')


if __name__ == '__main__':
    main()
