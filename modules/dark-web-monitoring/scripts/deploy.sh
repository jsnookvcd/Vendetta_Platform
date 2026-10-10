#!/usr/bin/env bash
# Pull latest code, re-render config, rebuild, restart. Run on the instance via SSM.
# /opt/darkweb is a symlink to this module's directory inside the cloned repo.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$APP_DIR"
# git pull from the repo root (the .git lives above the module directory).
git -C "$APP_DIR" rev-parse --show-toplevel >/dev/null 2>&1 && git -C "$APP_DIR" pull --ff-only || true
bash scripts/render_env.sh "$APP_DIR/.env"
docker compose build --pull
docker compose up -d --remove-orphans
docker image prune -f >/dev/null
docker compose ps
