#!/bin/bash
# First boot: Docker, code checkout, config from SSM, start the stack, nightly backup cron.
set -euxo pipefail
dnf update -y
dnf install -y docker git cronie
systemctl enable --now docker crond
usermod -aG docker ec2-user

# Compose v2 plugin (arm64)
mkdir -p /usr/local/lib/docker/cli-plugins
COMPOSE_VER="$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -oP '"tag_name": "\K[^"]+')"
curl -fsSL "https://github.com/docker/compose/releases/download/$${COMPOSE_VER}/docker-compose-linux-aarch64" -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

mkdir -p /opt/darkweb
if [ -n "${repo_url}" ]; then
  git clone "${repo_url}" /opt/darkweb
fi

cat > /etc/profile.d/darkweb.sh <<EOF
export SSM_PREFIX=${ssm_prefix}
export AWS_REGION=${region}
EOF

# Ship container logs to CloudWatch (optional, cheap at this volume)
cat > /etc/docker/daemon.json <<'EOF'
{"log-driver":"awslogs","log-opts":{"awslogs-group":"/darkweb/containers","awslogs-create-group":"true"}}
EOF
systemctl restart docker

if [ -f /opt/darkweb/docker-compose.yml ]; then
  cd /opt/darkweb
  SSM_PREFIX=${ssm_prefix} AWS_REGION=${region} bash scripts/render_env.sh /opt/darkweb/.env
  docker compose up -d --build
fi

# Nightly DB dump to S3 at 05:30 UTC
echo "30 5 * * * root cd /opt/darkweb && bash scripts/backup_db.sh >> /var/log/darkweb-backup.log 2>&1" > /etc/cron.d/darkweb-backup
