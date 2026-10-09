#!/usr/bin/env bash
# Renders /opt/darkweb/.env from SSM Parameter Store. Runs on boot and on `deploy.sh`.
# Parameters live under /darkweb/<KEY>; SecureString for secrets.
set -euo pipefail
PREFIX="${SSM_PREFIX:-/darkweb}"
REGION="${AWS_REGION:-$(curl -s http://169.254.169.254/latest/meta-data/placement/region)}"
OUT="${1:-/opt/darkweb/.env}"
aws ssm get-parameters-by-path --region "$REGION" --path "$PREFIX" --with-decryption --recursive \
  --query 'Parameters[].[Name,Value]' --output text \
  | while IFS=$'\t' read -r name value; do
      key="${name#"$PREFIX"/}"
      printf '%s=%s\n' "$key" "$value"
    done > "$OUT.tmp"
echo "AWS_REGION=$REGION" >> "$OUT.tmp"
chmod 600 "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "rendered $OUT with $(wc -l < "$OUT") keys"
