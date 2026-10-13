#!/bin/bash
# First boot for the shared platform host: Docker, code checkout from the private
# repo via a read-only deploy key, then each module's stack brought up from its own
# directory with an .env rendered from SSM. One host runs the control plane, the IR
# hub, managed services and dark web, each its own compose project on its own port.
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

if [ ! -d "$APP_ROOT/.git" ] && [ -n "${repo_url}" ]; then
  git clone --branch "${git_ref}" "${repo_url}" "$APP_ROOT" || true
fi

# Render a module's .env from SSM: the JSON _defaults blob written by Terraform,
# the per-module SECRET_KEY and POSTGRES_PASSWORD, plus any extra scalar params an
# operator put under <ssm_prefix>/<key>/ (tool credentials, Entra, PLATFORM_TOKEN).
render_env () {
  local key="$1" dir="$2" envfile="$3"
  : > "$envfile"
  aws ssm get-parameter --region "${region}" --name "${ssm_prefix}/$${key}/_defaults" \
      --query 'Parameter.Value' --output text 2>/dev/null \
    | jq -r 'to_entries[] | "\(.key)=\(.value)"' >> "$envfile" || true
  for p in SECRET_KEY POSTGRES_PASSWORD; do
    v=$(aws ssm get-parameter --region "${region}" --name "${ssm_prefix}/$${key}/$${p}" \
          --with-decryption --query 'Parameter.Value' --output text 2>/dev/null || true)
    [ -n "$v" ] && echo "$${p}=$${v}" >> "$envfile"
  done
  # Flat scalar params the operator added by hand, e.g. .../managed-services/SENTINELONE_API_TOKEN.
  aws ssm get-parameters-by-path --region "${region}" --path "${ssm_prefix}/$${key}/" \
      --with-decryption --recursive --query 'Parameters[].[Name,Value]' --output text 2>/dev/null \
    | while read -r name value; do
        base=$(basename "$name")
        case "$base" in _defaults|SECRET_KEY|POSTGRES_PASSWORD) continue;; esac
        echo "$${base}=$${value}" >> "$envfile"
      done || true
}

IFS=',' read -ra MODS <<< "${modules_csv}"
for entry in "$${MODS[@]}"; do
  key="$${entry%%:*}"; rest="$${entry#*:}"; subdir="$${rest%%:*}"
  dir="$APP_ROOT/$${subdir}"
  [ -f "$dir/docker-compose.yml" ] || continue
  render_env "$key" "$dir" "$dir/.env"
  ( cd "$dir" && docker compose --project-name "vcd-$${key}" up -d --build ) || true
done

# Nightly DB dump to S3 for each module that ships a backup script.
cat > /etc/cron.d/vendetta-backup <<EOF
30 5 * * * root for d in $APP_ROOT/modules/*/; do [ -f "\$d/scripts/backup_db.sh" ] && (cd "\$d" && bash scripts/backup_db.sh); done >> /var/log/vendetta-backup.log 2>&1
EOF
