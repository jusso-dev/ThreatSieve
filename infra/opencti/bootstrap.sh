#!/bin/bash
# Arguments: region, Secrets Manager ARN. Secret values never enter user data.
set -euo pipefail
umask 077
REGION="$1"
SECRET_ARN="$2"
dnf install -y docker
install -d -m 700 /opt/opencti
install -d /usr/local/lib/docker/cli-plugins
curl --fail --location --retry 3 https://github.com/docker/compose/releases/download/v5.6.0/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
printf '%s  %s\n' 40343e21ca777173e69cff5dbafeb37c6f81f3b0d57d9e597f036e95eb63e76a /usr/local/lib/docker/cli-plugins/docker-compose | sha256sum -c -
chmod 755 /usr/local/lib/docker/cli-plugins/docker-compose
curl --fail --location --retry 3 https://github.com/docker/buildx/releases/download/v0.37.2/buildx-v0.37.2.linux-amd64 -o /usr/local/lib/docker/cli-plugins/docker-buildx
printf '%s  %s\n' 982ca20490b45ed1ec8d99795974d3d874a358f75938c9c237305010e6b7e548 /usr/local/lib/docker/cli-plugins/docker-buildx | sha256sum -c -
chmod 755 /usr/local/lib/docker/cli-plugins/docker-buildx
printf 'vm.max_map_count=1048576\n' > /etc/sysctl.d/90-opencti.conf
sysctl --system >/dev/null
aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_ARN" --query SecretString --output text > /opt/opencti/secret.json
python3 - <<'PY'
import json, pathlib
root=pathlib.Path('/opt/opencti')
values=json.loads((root/'secret.json').read_text())
# Single quoted Compose values prevent accidental interpolation.
(root/'.env').write_text('\n'.join(k+"='"+v.replace("'", "\\'")+"'" for k,v in values.items())+'\n')
(root/'.env').chmod(0o600)
(root/'secret.json').unlink()
PY
cat > /etc/systemd/system/opencti.service <<'UNIT'
[Unit]
Description=ThreatSieve OpenCTI stack
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/opencti
ExecStart=/usr/bin/docker compose up --detach --build --wait --wait-timeout 900
ExecStop=/usr/bin/docker compose stop
TimeoutStartSec=1800
TimeoutStopSec=180
[Install]
WantedBy=multi-user.target
UNIT
systemctl enable --now docker
systemctl daemon-reload
systemctl enable --now opencti
