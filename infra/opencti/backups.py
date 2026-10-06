#!/usr/bin/env python3
"""Create an idempotent daily encrypted-EBS snapshot policy for OpenCTI volumes."""
import json
import subprocess
import sys

region = sys.argv[1]
name = 'threatsieve-opencti-backups'


def aws(*args):
    out = subprocess.check_output(['aws', '--region', region, *args, '--output', 'json'], text=True)
    return json.loads(out) if out.strip() else {}


roles = aws('iam', 'list-roles')['Roles']
role = next((r for r in roles if r['RoleName'] == name), None)
if role is None:
    role = aws('iam', 'create-role', '--role-name', name, '--assume-role-policy-document', json.dumps({
        'Version': '2012-10-17', 'Statement': [{'Effect':'Allow','Principal':{'Service':'dlm.amazonaws.com'},'Action':'sts:AssumeRole'}]
    }))['Role']
    aws('iam', 'attach-role-policy', '--role-name', name, '--policy-arn', 'arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole')
existing = aws('dlm', 'get-lifecycle-policies')['Policies']
policy = next((p for p in existing if p.get('Description') == name), None)
if policy is None:
    policy = aws('dlm', 'create-lifecycle-policy', '--description', name, '--state', 'ENABLED',
        '--execution-role-arn', role['Arn'], '--policy-details', json.dumps({
            'PolicyType':'EBS_SNAPSHOT_MANAGEMENT','ResourceTypes':['VOLUME'],
            'TargetTags':[{'Key':'ThreatSieveBackup','Value':'OpenCTI'}],
            'Schedules':[{'Name':'Daily','CopyTags':True,'CreateRule':{'Interval':24,'IntervalUnit':'HOURS','Times':['16:00']},'RetainRule':{'Count':7}}]
        }))
print(json.dumps(policy))
