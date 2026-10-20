#!/usr/bin/env bash
# Copy the per-module SSM parameters from the single-host account into a
# soc-apps account, and generate the same set for modules that never ran on the
# host. Values go from one API call to the next through stdin; nothing is
# printed, written to disk or passed on a command line.
#
# Usage:
#   SRC_PROFILE=vcd-platform DST_PROFILE=vcd-soc-apps-prod \
#     infra/aws/scripts/copy-ssm-params.sh [--overwrite]
#
# Needs: aws CLI v2, jq, python3 with the bcrypt package (for new modules only).
# DATABASE_URL is not copied: the database bootstrap writes it (README.md).
set -euo pipefail

PREFIX="${SSM_PREFIX:-/vendetta}"
REGION="${AWS_REGION:-us-east-1}"
SRC_PROFILE="${SRC_PROFILE:?set SRC_PROFILE to the host account profile}"
DST_PROFILE="${DST_PROFILE:?set DST_PROFILE to the soc-apps account profile}"
OVERWRITE="false"
[[ "${1:-}" == "--overwrite" ]] && OVERWRITE="true"

# Modules that ran on the host (infra/terraform modules map) and modules that
# start on ECS. Keep in step with soc-apps var.modules.
HOST_MODULES=(platform incident-response managed-services dark-web-monitoring vulnerability-management penetration-testing sabine professional-services mdr)
NEW_MODULES=(evidence-export ai-triage ingest)

src() { aws --profile "$SRC_PROFILE" --region "$REGION" "$@"; }
dst() { aws --profile "$DST_PROFILE" --region "$REGION" "$@"; }

exists() {
  dst ssm get-parameter --name "$1" --query Parameter.Name --output text >/dev/null 2>&1
}

# put NAME TYPE: reads the value on stdin.
put() {
  local name="$1" type="$2"
  if [[ "$OVERWRITE" != "true" ]] && exists "$name"; then
    echo "skip   $name (exists)"
    cat >/dev/null
    return
  fi
  jq -Rs --arg n "$name" --arg t "$type" --argjson o "$OVERWRITE" \
    '{Name: $n, Type: $t, Value: (. | rtrimstr("\n")), Tier: "Intelligent-Tiering", Overwrite: $o}' |
    dst ssm put-parameter --cli-input-json file:///dev/stdin >/dev/null
  echo "wrote  $name"
}

copy_module() {
  local module="$1" next="" page
  while :; do
    if [[ -n "$next" ]]; then
      page="$(src ssm get-parameters-by-path --path "$PREFIX/$module" --with-decryption --starting-token "$next" --output json)"
    else
      page="$(src ssm get-parameters-by-path --path "$PREFIX/$module" --with-decryption --output json)"
    fi
    while IFS= read -r row; do
      local name type
      name="$(jq -r '.Name' <<<"$row")"
      type="$(jq -r '.Type' <<<"$row")"
      jq -j '.Value' <<<"$row" | put "$name" "$type"
    done < <(jq -c '.Parameters[]' <<<"$page")
    next="$(jq -r '.NextToken // empty' <<<"$page")"
    [[ -z "$next" ]] && break
  done
}

gen_module() {
  local module="$1"
  python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(64)),end="")' | put "$PREFIX/$module/SECRET_KEY" SecureString
  python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(48)),end="")' | put "$PREFIX/$module/API_TOKEN" SecureString
  python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode(),end="")' | put "$PREFIX/$module/ENCRYPTION_KEY" SecureString
  python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(32)),end="")' | put "$PREFIX/$module/POSTGRES_PASSWORD" SecureString

  if [[ "$OVERWRITE" == "true" ]] || ! exists "$PREFIX/$module/ADMIN_PASSWORD"; then
    local pw
    pw="$(python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(24)),end="")')"
    printf '%s' "$pw" | put "$PREFIX/$module/ADMIN_PASSWORD" SecureString
    printf '%s' "$pw" | python3 -c 'import sys,bcrypt;print(bcrypt.hashpw(sys.stdin.read().encode(),bcrypt.gensalt(12)).decode(),end="")' |
      put "$PREFIX/$module/ADMIN_PASSWORD_HASH" SecureString
    unset pw
  fi

  # Client modules present the control plane's token, as on the host.
  dst ssm get-parameter --name "$PREFIX/platform/API_TOKEN" --with-decryption --query Parameter.Value --output text |
    put "$PREFIX/$module/PLATFORM_TOKEN" SecureString
}

for m in "${HOST_MODULES[@]}"; do
  copy_module "$m"
done

for m in "${NEW_MODULES[@]}"; do
  gen_module "$m"
done

echo "done. Next: database bootstrap (writes $PREFIX/<module>/DATABASE_URL), then re-render MODULE_DIRECTORY if hostnames changed."
