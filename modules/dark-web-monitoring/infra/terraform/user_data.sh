#!/bin/bash
# First boot: Docker, code checkout from the private platform repo via a read-only
# deploy key, config from SSM, start the stack from the module subdirectory, nightly
# backup cron. The hosting unit is this module's directory inside the monorepo.
set -euxo pipefail

APP_ROOT=/opt/vendetta_platform
APP_DIR="$APP_ROOT/${module_subdir}"

dnf update -y
dnf install -y docker git cronie
command -v aws >/dev/null 2>&1 || dnf install -y awscli
systemctl enable --now docker crond
usermod -aG docker ec2-user

# Docker Compose v2 plugin, pinned (arm64 / Graviton).
COMPOSE_VER="v2.29.7"
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/download/$${COMPOSE_VER}/docker-compose-linux-aarch64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Ship container logs to CloudWatch (cheap at this volume).
cat > /etc/docker/daemon.json <<'EOF'
{"log-driver":"awslogs","log-opts":{"awslogs-group":"/darkweb/containers","awslogs-create-group":"true"}}
EOF
systemctl restart docker

cat > /etc/profile.d/darkweb.sh <<EOF
export SSM_PREFIX=${ssm_prefix}
export AWS_REGION=${region}
export APP_DIR=$APP_DIR
EOF

# Read-only deploy key for the private repo, stored as an SSM SecureString.
mkdir -p /root/.ssh && chmod 700 /root/.ssh
if aws ssm get-parameter --region "${region}" --name "${ssm_prefix}/DEPLOY_KEY" --with-decryption \
     --query 'Parameter.Value' --output text > /root/.ssh/id_ed25519 2>/dev/null; then
  chmod 600 /root/.ssh/id_ed25519
  ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts 2>/dev/null
fi

if [ ! -d "$APP_ROOT/.git" ] && [ -n "${repo_url}" ]; then
  git clone --branch "${git_ref}" "${repo_url}" "$APP_ROOT" || true
fi

# /opt/darkweb points at the module dir so the deploy and backup scripts have one stable path.
ln -sfn "$APP_DIR" /opt/darkweb

if [ -f "$APP_DIR/docker-compose.yml" ]; then
  cd "$APP_DIR"
  SSM_PREFIX=${ssm_prefix} AWS_REGION=${region} bash scripts/render_env.sh "$APP_DIR/.env"
  docker compose up -d --build
fi

# Nightly DB dump to S3 at 05:30 UTC.
echo "30 5 * * * root cd /opt/darkweb && bash scripts/backup_db.sh >> /var/log/darkweb-backup.log 2>&1" > /etc/cron.d/darkweb-backup
