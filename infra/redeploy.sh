#!/usr/bin/env bash
# Redeploy the running platform host with the latest code on main.
#
# The host clones the repo once at boot (user_data) and does not pull on its own,
# so a code change on main goes live only when something pulls and rebuilds on the
# host. This script does that over SSM, with no SSH and no open ports: it sends a
# command to the instance that runs `git pull` in the repo, re-renders each
# module's .env from SSM (so a parameter you added or changed since the last deploy
# reaches the containers), and runs `docker compose up -d --build` for each module
# stack. Each module runs its own schema migration at container start, so new
# tables and columns apply automatically on restart.
#
# Usage:
#   infra/redeploy.sh                 # all modules, instance id from terraform output
#   infra/redeploy.sh managed-services
#   INSTANCE=i-0abc REGION=us-east-1 infra/redeploy.sh managed-services platform
#   SSM_PREFIX=/vendetta is where the module parameters live (the default)
#
# Requires: awscli v2 with SSM access to the instance (the same credentials you use
# for the rest of GO_LIVE) and jq.
set -euo pipefail

command -v jq >/dev/null 2>&1 || { echo "jq is required." >&2; exit 2; }

REGION="${REGION:-us-east-1}"
APP_ROOT="${APP_ROOT:-/opt/vendetta_platform}"
SSM_PREFIX="${SSM_PREFIX:-/vendetta}"
GIT_REF="${GIT_REF:-main}"

# Resolve the instance id from Terraform output unless one was passed in the env.
INSTANCE="${INSTANCE:-}"
if [ -z "$INSTANCE" ]; then
  if command -v terraform >/dev/null 2>&1; then
    INSTANCE="$(terraform -chdir="$(dirname "$0")/terraform" output -raw instance_id 2>/dev/null || true)"
  fi
fi
if [ -z "$INSTANCE" ]; then
  echo "No instance id. Set INSTANCE=i-... or run from a tree where 'terraform output instance_id' works." >&2
  exit 2
fi

# Module directory names under modules/ map one-to-one to the compose project
# names the host uses (vcd-<name>). With no args, every module with a compose file
# is rebuilt; otherwise only the named ones.
MODULES=("$@")

echo "Redeploying ${INSTANCE} (${REGION}) from ${GIT_REF}: ${MODULES[*]:-all modules}"

# Build the remote script. It runs as root on the instance.
read -r -d '' REMOTE <<REMOTE_EOF || true
set -euo pipefail
cd "${APP_ROOT}"
echo "== git pull =="
git fetch --all --prune
git checkout "${GIT_REF}"
git pull --ff-only
echo "== host helpers =="
install -m 0755 "${APP_ROOT}/infra/host/vendetta-env" /usr/local/sbin/vendetta-env
install -m 0755 "${APP_ROOT}/infra/host/vendetta-backup" /usr/local/sbin/vendetta-backup
docker network inspect vendetta >/dev/null 2>&1 || docker network create vendetta
echo "== render config and rebuild =="
want="${MODULES[*]:-}"
for dir in "${APP_ROOT}"/modules/*/; do
  key="\$(basename "\$dir")"
  [ -f "\$dir/docker-compose.yml" ] || continue
  if [ -n "\$want" ] && ! echo " \$want " | grep -q " \$key "; then continue; fi
  echo "-- \$key --"
  AWS_REGION="${REGION}" SSM_PREFIX="${SSM_PREFIX}" vendetta-env "\$key" "\$dir"
  ( cd "\$dir" && docker compose --project-name "vcd-\$key" up -d --build )
done
docker image prune -f >/dev/null || true
echo "== status =="
for dir in "${APP_ROOT}"/modules/*/; do
  key="\$(basename "\$dir")"
  [ -f "\$dir/docker-compose.yml" ] || continue
  ( cd "\$dir" && docker compose --project-name "vcd-\$key" ps ) || true
done
REMOTE_EOF

# Pass the script as proper JSON so newlines and commas survive (the commands=
# shorthand would split the script on every comma).
PARAMS="$(jq -n --arg s "$REMOTE" '{commands: [$s]}')"
CMD_ID="$(aws ssm send-command \
  --region "$REGION" \
  --instance-ids "$INSTANCE" \
  --document-name "AWS-RunShellScript" \
  --comment "vendetta redeploy ${GIT_REF}" \
  --parameters "$PARAMS" \
  --query 'Command.CommandId' --output text)"

echo "SSM command: $CMD_ID  (waiting for completion)"
aws ssm wait command-executed --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" || true

STATUS="$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
  --instance-id "$INSTANCE" --query 'Status' --output text)"
echo "---- output ----"
aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
  --instance-id "$INSTANCE" --query 'StandardOutputContent' --output text
ERR="$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
  --instance-id "$INSTANCE" --query 'StandardErrorContent' --output text)"
[ -n "$ERR" ] && { echo "---- stderr ----"; echo "$ERR"; }
echo "---- status: ${STATUS} ----"
[ "$STATUS" = "Success" ]
