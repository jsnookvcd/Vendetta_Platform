#!/bin/bash
# First boot for the shared platform host: Docker, code checkout from the private
# repo via a read-only deploy key, then each module's stack brought up from its own
# directory with an .env rendered from SSM by infra/host/vendetta-env. One host runs
# every built module, each its own compose project on its own port, all joined to
# one docker network so they reach each other by module name.
set -euxo pipefail

APP_ROOT=/opt/vendetta_platform

dnf update -y
dnf install -y docker git cronie jq
command -v aws >/dev/null 2>&1 || dnf install -y awscli
systemctl enable --now docker crond
usermod -aG docker ec2-user

COMPOSE_VER="v2.29.7"
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/download/$${COMPOSE_VER}/docker-compose-linux-aarch64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

cat > /etc/docker/daemon.json <<'EOF'
{"log-driver":"awslogs","log-opts":{"awslogs-group":"/vendetta/containers","awslogs-create-group":"true"}}
EOF
systemctl restart docker

# Read-only deploy key for the private repo.
mkdir -p /root/.ssh && chmod 700 /root/.ssh
if aws ssm get-parameter --region "${region}" --name "${ssm_prefix}/DEPLOY_KEY" --with-decryption \
     --query 'Parameter.Value' --output text > /root/.ssh/id_ed25519 2>/dev/null; then
  chmod 600 /root/.ssh/id_ed25519
  ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts 2>/dev/null
fi

if [ ! -d "$APP_ROOT/.git" ]; then
  if [ -z "${repo_url}" ]; then echo "no repo_url set; nothing to deploy" >&2; exit 2; fi
  # A failed clone must be loud: an empty host with no error is the worst outcome.
  git clone --branch "${git_ref}" "${repo_url}" "$APP_ROOT"
fi

# Host helpers from the repo: the .env renderer (also used by every redeploy) and
# the nightly backup. Installed on every boot so a code update refreshes them.
install -m 0755 "$APP_ROOT/infra/host/vendetta-env" /usr/local/sbin/vendetta-env
install -m 0755 "$APP_ROOT/infra/host/vendetta-backup" /usr/local/sbin/vendetta-backup

# The shared cross-module network every stack joins (compose declares it external).
docker network inspect vendetta >/dev/null 2>&1 || docker network create vendetta

failed=""
IFS=',' read -ra MODS <<< "${modules_csv}"
for entry in "$${MODS[@]}"; do
  key="$${entry%%:*}"; rest="$${entry#*:}"; subdir="$${rest%%:*}"
  dir="$APP_ROOT/$${subdir}"
  if [ ! -f "$dir/docker-compose.yml" ]; then echo "$${key}: no compose file, skipping" >&2; continue; fi
  if ! AWS_REGION="${region}" SSM_PREFIX="${ssm_prefix}" vendetta-env "$${key}" "$dir"; then
    failed="$failed $${key}"; continue
  fi
  if ! ( cd "$dir" && docker compose --project-name "vcd-$${key}" up -d --build ); then
    echo "$${key}: compose up failed" >&2; failed="$failed $${key}"
  fi
done

# Nightly DB dump of every module to the backups bucket (05:30 UTC).
cat > /etc/cron.d/vendetta-backup <<CRON
30 5 * * * root AWS_REGION=${region} /usr/local/sbin/vendetta-backup $APP_ROOT >> /var/log/vendetta-backup.log 2>&1
CRON

if [ -n "$failed" ]; then echo "first boot finished with failures:$failed" >&2; exit 1; fi
echo "first boot complete"
