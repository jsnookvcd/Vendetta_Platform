#!/usr/bin/env bash
# Nightly Postgres dump to the evidence bucket under backups/. Installed as a cron job by user_data.
set -euo pipefail
cd /opt/darkweb
BUCKET="$(grep '^EVIDENCE_BUCKET=' .env | cut -d= -f2-)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose exec -T db pg_dump -U darkweb darkweb | gzip > "/tmp/darkweb-$STAMP.sql.gz"
if [ -n "$BUCKET" ]; then
  aws s3 cp "/tmp/darkweb-$STAMP.sql.gz" "s3://$BUCKET/backups/darkweb-$STAMP.sql.gz" --only-show-errors
fi
rm -f "/tmp/darkweb-$STAMP.sql.gz"
