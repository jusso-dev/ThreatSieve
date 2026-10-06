#!/usr/bin/env python3
"""Replace bootstrap connector access with OpenCTI's dedicated Connector role.
Usage: service-account.py REGION SECRET_ARN LOCAL_SSM_HTTP_ORIGIN
Requires an active SSM port-forward; credentials never appear in output.
"""
import json
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

region, secret_arn, origin = sys.argv[1:]
parsed = urllib.parse.urlparse(origin)
if parsed.scheme != 'http' or parsed.hostname not in ('localhost', '127.0.0.1'):
    raise ValueError('Use a local SSM port-forward origin')
secret = json.loads(subprocess.check_output([
    'aws','--region',region,'secretsmanager','get-secret-value','--secret-id',secret_arn,
    '--query','SecretString','--output','text'],text=True))


def query(document, variables=None):
    request = urllib.request.Request(origin+'/graphql', method='POST',
        headers={'Authorization':'Bearer '+secret['OPENCTI_ADMIN_TOKEN'],'Content-Type':'application/json'},
        data=json.dumps({'query':document,'variables':variables or {}}).encode())
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    if result.get('errors'):
        raise RuntimeError('OpenCTI service-account operation rejected')
    return result['data']


if secret.get('OPENCTI_CONNECTOR_TOKEN'):
    print('Connector token already provisioned; rotate it explicitly before expiry.')
    sys.exit(0)

groups = query('query { groups { edges { node { id name } } } }')['groups']['edges']
group_id = next(g['node']['id'] for g in groups if g['node']['name'] == 'Connectors')
users = query('query { users(search:"ThreatSieve connector") { edges { node { id name } } } }')['users']['edges']
user = next((u['node'] for u in users if u['node']['name'] == 'ThreatSieve connector'), None)
if user is None:
    user = query('mutation($input:UserAddInput!) { userAdd(input:$input) { id name } }',
        {'input':{'name':'ThreatSieve connector','user_email':'threatsieve-connector@localhost.invalid','groups':[group_id],'prevent_default_groups':True,'user_service_account':True}})['userAdd']
token = query('mutation($userId:ID!,$input:UserTokenAddInput!) { userAdminTokenAdd(userId:$userId,input:$input) { plaintext_token expires_at } }',
    {'userId':user['id'],'input':{'name':'ThreatSieve import connector','duration':'DAYS_365'}})['userAdminTokenAdd']
secret['OPENCTI_CONNECTOR_TOKEN'] = token['plaintext_token']
secret['OPENCTI_CONNECTOR_TOKEN_EXPIRES_AT'] = token['expires_at']
with tempfile.NamedTemporaryFile(mode='w') as file:
    json.dump(secret,file)
    file.flush()
    subprocess.run(['aws','--region',region,'secretsmanager','put-secret-value','--secret-id',secret_arn,
                    '--secret-string','file://'+file.name],check=True,stdout=subprocess.DEVNULL)
print('Dedicated Connector-role token saved in Secrets Manager. Refresh the host configuration and recreate the connector container.')
