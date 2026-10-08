#!/usr/bin/env python3
"""Provision a read-only OpenCTI TAXII collection for ThreatSieve's TAXII 2.1 feed.
Usage: taxii-reader.py REGION SECRET_ARN LOCAL_SSM_HTTP_ORIGIN
Requires an active SSM port-forward; credentials never appear in output.

Creates a "ThreatSieve TAXII reader" service account whose group may only read
knowledge through TAXII and only sees TLP:CLEAR/GREEN and PAP:CLEAR/GREEN (plus
public MITRE statements). AMBER/RED intelligence never leaves OpenCTI. The
collection excludes objects authored by the ThreatSieve connector identity so
ThreatSieve does not re-import its own assessments. (All OpenCTI connectors share
one connector account, so creator_id cannot distinguish them; createdBy can.
Deliveries made before the dedicated connector account existed are authored by
the bootstrap admin identity, so it is excluded too.)
"""
import json
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

ROLE = 'TAXII reader'
GROUP = 'ThreatSieve TAXII readers'
USER = 'ThreatSieve TAXII reader'
COLLECTION = 'ThreatSieve import'
THREATSIEVE_AUTHORS = ('ThreatSieve connector', 'admin')
SHAREABLE = ('TLP:CLEAR', 'TLP:GREEN', 'PAP:CLEAR', 'PAP:GREEN')

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
        raise RuntimeError('OpenCTI TAXII reader operation rejected: '+result['errors'][0].get('message','')[:120])
    return result['data']


def named(kind, name, fields='id name'):
    edges = query('query($s:String){ %s(search:$s) { edges { node { %s } } } }' % (kind, fields), {'s': name})[kind]['edges']
    return next((e['node'] for e in edges if e['node']['name'] == name), None)


if secret.get('OPENCTI_TAXII_TOKEN'):
    print('TAXII reader token already provisioned; rotate it explicitly before expiry.')
    sys.exit(0)

capabilities = {e['node']['name']: e['node']['id'] for e in
    query('{ capabilities(first:500) { edges { node { id name } } } }')['capabilities']['edges']}
role = named('roles', ROLE) or query('mutation($i:RoleAddInput!) { roleAdd(input:$i) { id name } }',
    {'i': {'name': ROLE, 'description': 'Read knowledge through TAXII only'}})['roleAdd']
for capability in ('KNOWLEDGE', 'TAXIIAPI', 'APIACCESS_USETOKEN'):
    query('mutation($id:ID!,$i:InternalRelationshipAddInput!) { roleEdit(id:$id) { relationAdd(input:$i) { id } } }',
        {'id': role['id'], 'i': {'toId': capabilities[capability], 'relationship_type': 'has-capability'}})

group = named('groups', GROUP) or query('mutation($i:GroupAddInput!) { groupAdd(input:$i) { id name } }',
    {'i': {'name': GROUP, 'description': 'ThreatSieve TAXII import; shareable markings only',
           'default_assignation': False, 'no_creators': True,
           'group_confidence_level': {'max_confidence': 100, 'overrides': []}}})['groupAdd']
query('mutation($id:ID!,$i:InternalRelationshipAddInput!) { groupEdit(id:$id) { relationAdd(input:$i) { id } } }',
    {'id': group['id'], 'i': {'toId': role['id'], 'relationship_type': 'has-role'}})
markings = query('{ markingDefinitions(first:200) { edges { node { id definition definition_type } } } }')['markingDefinitions']['edges']
for marking in markings:
    node = marking['node']
    if node['definition'] in SHAREABLE or node['definition_type'] == 'statement':
        query('mutation($id:ID!,$i:InternalRelationshipAddInput!) { groupEdit(id:$id) { relationAdd(input:$i) { id } } }',
            {'id': group['id'], 'i': {'toId': node['id'], 'relationship_type': 'accesses-to'}})

user = named('users', USER) or query('mutation($i:UserAddInput!) { userAdd(input:$i) { id name } }',
    {'i': {'name': USER, 'user_email': 'threatsieve-taxii@localhost.invalid', 'groups': [group['id']],
           'prevent_default_groups': True, 'user_service_account': True}})['userAdd']

authors = [a['id'] for a in (named('identities', n) for n in THREATSIEVE_AUTHORS) if a]
filters = {'mode': 'and', 'filterGroups': [], 'filters': [] if not authors else [
    {'key': ['createdBy'], 'values': authors, 'operator': 'not_eq', 'mode': 'and'}]}
collection = named('taxiiCollections', COLLECTION) or query(
    'mutation($i:TaxiiCollectionAddInput!) { taxiiCollectionAdd(input:$i) { id name } }',
    {'i': {'name': COLLECTION, 'description': 'Shareable OpenCTI knowledge for ThreatSieve (excludes ThreatSieve-created objects)',
           'filters': json.dumps(filters), 'taxii_public': False, 'include_inferences': False,
           'score_to_confidence': True, 'authorized_members': [{'id': group['id'], 'access_right': 'view'}]}})['taxiiCollectionAdd']

token = query('mutation($userId:ID!,$input:UserTokenAddInput!) { userAdminTokenAdd(userId:$userId,input:$input) { plaintext_token expires_at } }',
    {'userId': user['id'], 'input': {'name': 'ThreatSieve TAXII feed', 'duration': 'DAYS_365'}})['userAdminTokenAdd']
secret['OPENCTI_TAXII_TOKEN'] = token['plaintext_token']
secret['OPENCTI_TAXII_TOKEN_EXPIRES_AT'] = token['expires_at']
secret['OPENCTI_TAXII_COLLECTION_ID'] = collection['id']
with tempfile.NamedTemporaryFile(mode='w') as file:
    json.dump(secret, file)
    file.flush()
    subprocess.run(['aws','--region',region,'secretsmanager','put-secret-value','--secret-id',secret_arn,
                    '--secret-string','file://'+file.name],check=True,stdout=subprocess.DEVNULL)
print('TAXII collection '+collection['id']+' ready; reader token saved in Secrets Manager.')
