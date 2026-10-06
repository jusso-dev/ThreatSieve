#!/usr/bin/env python3
"""Provision one private OpenCTI host using the caller's AWS session.

Usage: provision.py REGION VPC_ID SUBNET_ID ADMIN_EMAIL CONNECTOR_KEY_FILE
The connector key file must contain {"key": "..."}; it is never printed.
"""
import base64
import io
import json
import pathlib
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
NAME = 'threatsieve-opencti-production'
update_template = '--update-template' in sys.argv
region, vpc, subnet, email, key_file = [a for a in sys.argv[1:] if a != '--update-template']


def aws(*args):
    result = subprocess.run(['aws', '--region', region, *args, '--output', 'json'],
                            capture_output=True, text=True)
    if result.returncode:
        # AWS errors can include request parameters; never print raw stderr.
        raise RuntimeError('AWS operation failed: ' + ' '.join(args[:2]))
    return json.loads(result.stdout) if result.stdout.strip() else {}


def document_call(service, operation, flag, document, *args):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
        json.dump(document, file)
        file.flush()
        return aws(service, operation, flag, 'file://' + file.name, *args)


account = aws('sts', 'get-caller-identity')['Account']
network = aws('ec2', 'describe-subnets', '--subnet-ids', subnet)['Subnets'][0]
if network['VpcId'] != vpc or network['MapPublicIpOnLaunch']:
    raise ValueError('Choose a private subnet in the supplied VPC, with NAT/SSM connectivity')
existing = aws('ec2', 'describe-instances', '--filters', 'Name=tag:Name,Values='+NAME,
               'Name=instance-state-name,Values=pending,running,stopping,stopped')['Reservations']
if existing and not update_template:
    print('Existing OpenCTI host: '+existing[0]['Instances'][0]['InstanceId'])
    sys.exit(0)

keys = json.loads(pathlib.Path(key_file).read_text())
secret_name = NAME + '/configuration'
secret_list = aws('secretsmanager', 'list-secrets', '--filters', 'Key=name,Values='+secret_name)['SecretList']
if secret_list:
    secret_arn = next(s['ARN'] for s in secret_list if s['Name'] == secret_name)
else:
    values = {
        'OPENCTI_ADMIN_EMAIL': email,
        'OPENCTI_ADMIN_PASSWORD': secrets.token_hex(32),
        'OPENCTI_ADMIN_TOKEN': str(uuid.uuid4()),
        'OPENCTI_ENCRYPTION_KEY': secrets.token_hex(32),
        'OPENCTI_HEALTHCHECK_ACCESS_KEY': secrets.token_hex(32),
        'MINIO_ROOT_USER': 'opencti', 'MINIO_ROOT_PASSWORD': secrets.token_hex(32),
        'RABBITMQ_DEFAULT_USER': 'opencti', 'RABBITMQ_DEFAULT_PASS': secrets.token_hex(32),
        'CONNECTOR_ID': str(uuid.uuid4()),
        'THREATSIEVE_URL': keys['url'], 'THREATSIEVE_API_KEY': keys['key'],
    }
    secret_arn = document_call('secretsmanager', 'create-secret', '--cli-input-json', {
        'Name': secret_name, 'SecretString': json.dumps(values),
        'Tags': [{'Key': 'Application', 'Value': 'ThreatSieve'}],
    })['ARN']

role_name = NAME + '-host'
roles = aws('iam', 'list-roles')['Roles']
if not any(r['RoleName'] == role_name for r in roles):
    document_call('iam', 'create-role', '--assume-role-policy-document', {
        'Version':'2012-10-17', 'Statement':[{'Effect':'Allow','Principal':{'Service':'ec2.amazonaws.com'},'Action':'sts:AssumeRole'}]
    }, '--role-name', role_name)
    aws('iam', 'attach-role-policy', '--role-name', role_name, '--policy-arn',
        'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')
    aws('iam', 'create-instance-profile', '--instance-profile-name', role_name)
    aws('iam', 'add-role-to-instance-profile', '--instance-profile-name', role_name, '--role-name', role_name)
document_call('iam', 'put-role-policy', '--policy-document', {
    'Version':'2012-10-17', 'Statement':[{'Effect':'Allow','Action':['secretsmanager:GetSecretValue'],'Resource':secret_arn}]
}, '--role-name', role_name, '--policy-name', 'ReadOpenCTIConfiguration')

security_groups = aws('ec2', 'describe-security-groups', '--filters', 'Name=group-name,Values='+NAME,
                      'Name=vpc-id,Values='+vpc)['SecurityGroups']
sg = security_groups[0]['GroupId'] if security_groups else aws(
    'ec2','create-security-group','--group-name',NAME,'--description','OpenCTI: no inbound access; use SSM forwarding','--vpc-id',vpc)['GroupId']
if security_groups and security_groups[0]['IpPermissions']:
    raise ValueError('Existing OpenCTI security group has inbound rules; refusing to reuse')

archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w:gz') as tar:
    for source, target in [
        ('infra/opencti/compose.yaml','compose.yaml'),
        ('infra/opencti/bootstrap.sh','bootstrap.sh'),
        ('connectors/opencti/Dockerfile','connector/Dockerfile'),
        ('connectors/opencti/requirements.txt','connector/requirements.txt'),
        ('connectors/opencti/connector.py','connector/connector.py'),
    ]:
        tar.add(ROOT/source, arcname=target)
userdata = '#!/bin/bash\nset -euo pipefail\numask 077\nmkdir -p /opt/opencti\nbase64 -d <<\'BUNDLE\' | tar -xz -C /opt/opencti\n'+base64.b64encode(archive.getvalue()).decode()+'\nBUNDLE\nbash /opt/opencti/bootstrap.sh '+region+' '+secret_arn+'\n'
if len(userdata.encode()) > 16384:
    raise ValueError('User data exceeds EC2 limit')
ami = aws('ssm','get-parameter','--name','/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64')['Parameter']['Value']
tags = [{'Key':'Name','Value':NAME},{'Key':'Application','Value':'ThreatSieve'},
        {'Key':'Environment','Value':'production'},{'Key':'ThreatSieveBackup','Value':'OpenCTI'}]
launch = {
    'ImageId':ami,'InstanceType':'r8i.xlarge',
    'IamInstanceProfile':{'Name':role_name},
    'NetworkInterfaces':[{'DeviceIndex':0,'SubnetId':subnet,'Groups':[sg],'AssociatePublicIpAddress':False}],
    'MetadataOptions':{'HttpTokens':'required','HttpPutResponseHopLimit':1},
    'Monitoring':{'Enabled':True}, 'DisableApiTermination':True,
    'BlockDeviceMappings':[{'DeviceName':'/dev/xvda','Ebs':{'VolumeSize':250,'VolumeType':'gp3','Encrypted':True,'DeleteOnTermination':False}}],
    'UserData':base64.b64encode(userdata.encode()).decode(),
    'TagSpecifications':[{'ResourceType':kind,'Tags':tags} for kind in ['instance','volume']],
}
templates = aws('ec2','describe-launch-templates','--filters','Name=launch-template-name,Values='+NAME)['LaunchTemplates']
if templates:
    version = document_call('ec2','create-launch-template-version','--launch-template-data',launch,'--launch-template-name',NAME)['LaunchTemplateVersion']['VersionNumber']
else:
    template = document_call('ec2','create-launch-template','--launch-template-data',launch,'--launch-template-name',NAME)['LaunchTemplate']
    version = template['LatestVersionNumber']
if update_template:
    print('Launch template updated to version '+str(version)+'; existing instance unchanged.')
    sys.exit(0)

# Allow propagation of the newly attached instance profile.
time.sleep(10)
instance = aws('ec2','run-instances','--launch-template',json.dumps({'LaunchTemplateName':NAME,'Version':str(version)}),
               '--count','1','--client-token',NAME)['Instances'][0]
state = {'instanceId':instance['InstanceId'],'region':region,'secretArn':secret_arn,'subnetId':subnet,
         'securityGroupId':sg,'launchTemplate':NAME,'launchTemplateVersion':version}
(ROOT/'artifacts/opencti-deployment.local.json').write_text(json.dumps(state,indent=2))
print(json.dumps(state,indent=2))
