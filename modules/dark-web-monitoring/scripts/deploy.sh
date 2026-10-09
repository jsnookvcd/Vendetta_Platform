#!/usr/bin/env bash
# Pull latest code, re-render config, rebuild, restart. Run on the instance via SSM Session Manager.
set -euo pipefail
cd /opt/darkweb
if [ -d .git ]; then git pull --ff-only; fi
bash scripts/render_env.sh /opt/darkweb/.env
docker compose build --pull
docker compose up -d --remove-orphans
docker image prune -f >/dev/null
docker compose ps
