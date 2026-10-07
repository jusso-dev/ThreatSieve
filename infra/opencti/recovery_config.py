"""Construct a connector-free, network-isolated Compose recovery workload.

Input is a resolved production Compose document. Call only on the private host;
resolved configuration contains secrets and must never enter command output.
"""
import copy
import secrets
import uuid

SERVICES = {'redis', 'elasticsearch', 'minio', 'rabbitmq', 'opencti'}
VOLUMES = {'redis', 'elastic', 'objects', 'rabbit'}


def recovery_config(source, rabbit_hostname):
    if not rabbit_hostname or not all(c.isalnum() or c == '-' for c in rabbit_hostname):
        raise ValueError('Invalid broker hostname')
    if not SERVICES.issubset(source.get('services', {})):
        raise ValueError('Missing required recovery service')
    result = {'name': 'threatsieve-recovery', 'services': {}, 'volumes': {},
              'networks': {'default': {'internal': True}}}
    for key in VOLUMES:
        name = source['volumes'][key]['name']
        if name != 'threatsieve-opencti_' + key:
            raise ValueError('Unexpected production volume identity')
        result['volumes'][key] = {'external': True, 'name': name}
    for name in sorted(SERVICES):
        original = source['services'][name]
        # Do not copy privileged mode, host networking, mounts, build hooks or
        # startup overrides from an unreviewed production configuration.
        allowed = {'image', 'command', 'environment', 'healthcheck', 'ulimits'}
        service = {k: copy.deepcopy(v) for k, v in original.items() if k in allowed}
        if 'image' not in service:
            raise ValueError('Recovery requires locally available images')
        service.update({'restart': 'no', 'pull_policy': 'never',
                        'security_opt': ['no-new-privileges:true'],
                        'networks': ['default']})
        mounts = original.get('volumes', [])
        for mount in mounts:
            if mount.get('type') != 'volume' or mount.get('source') not in VOLUMES:
                raise ValueError('Recovery rejects host bind mounts')
        service['volumes'] = copy.deepcopy(mounts)
        if name == 'rabbitmq':
            # RabbitMQ's on-disk Mnesia directory is keyed by its node hostname.
            service['hostname'] = rabbit_hostname
        if name == 'opencti':
            env = service['environment']
            # Keep the data encryption key, but use independent recovery login
            # credentials and no production connector tokens/API credentials.
            env['APP__ADMIN__TOKEN'] = str(uuid.uuid4())
            env['APP__ADMIN__PASSWORD'] = secrets.token_hex(32)
            env['APP__HEALTH_ACCESS_KEY'] = secrets.token_hex(32)
            env['APP__BASE_URL'] = 'http://localhost:8080'
        for key in service.get('environment', {}):
            if key.startswith(('THREATSIEVE_', 'CONNECTOR_', 'OPENCTI_TOKEN')):
                raise ValueError('Connector credentials are forbidden in recovery')
        result['services'][name] = service
    return result
