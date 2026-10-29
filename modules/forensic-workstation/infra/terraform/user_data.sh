#!/bin/bash
# First boot: check out the platform repo, then hand off to the module's
# provision.sh, which installs the toolset, Claude Code and the forensic MCP
# server. Provisioning takes 25 to 40 minutes; progress is in
# /var/log/forensic-provision.log and the login banner shows status.
set -euxo pipefail
exec > >(tee -a /var/log/forensic-provision.log) 2>&1

export DEBIAN_FRONTEND=noninteractive
APP_ROOT=/opt/vendetta_platform
APP_DIR="$APP_ROOT/${module_subdir}"

echo "PROVISIONING (started $(date -u +%FT%TZ)). Tools are not ready yet." > /etc/motd

apt-get update -y
apt-get install -y git curl unzip jq
if ! command -v aws >/dev/null 2>&1; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp && /tmp/aws/install
fi

# Optional read-only deploy key if the repo is private.
mkdir -p /root/.ssh && chmod 700 /root/.ssh
if aws ssm get-parameter --region "${region}" --name "${ssm_prefix}/DEPLOY_KEY" --with-decryption \
     --query 'Parameter.Value' --output text > /root/.ssh/id_ed25519 2>/dev/null; then
  chmod 600 /root/.ssh/id_ed25519
  ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts 2>/dev/null
else
  rm -f /root/.ssh/id_ed25519
fi

if [ ! -d "$APP_ROOT/.git" ]; then
  git clone --depth 1 --branch "${git_ref}" "${repo_url}" "$APP_ROOT"
fi
ln -sfn "$APP_DIR" /opt/forensic-workstation

SSM_PREFIX="${ssm_prefix}" AWS_REGION="${region}" ENABLE_DESKTOP="${enable_desktop}" \
  bash "$APP_DIR/scripts/provision.sh"
