#!/usr/bin/env bash
# Runs Vendetta's RansomLook instance: Tor, the Valkey/Redis cache, the API
# behind gunicorn, and a scrape and parse cycle every SCRAPE_INTERVAL_MINUTES.
set -euo pipefail
cd /opt/RansomLook

INTERVAL="${SCRAPE_INTERVAL_MINUTES:-60}"
WORKERS="${WEB_WORKERS:-2}"
BOOTSTRAP_FROM="${BOOTSTRAP_FROM:-https://www.ransomlook.io}"

# The cache directory is a volume; seed its config and launcher on first start.
for f in cache.conf run_redis.sh; do
  [ -f "cache/$f" ] || cp -a "/opt/ransomlook-cache-defaults/$f" "cache/$f"
done

echo "[vendetta] $(cat /opt/ransomlook-version)"
echo "[vendetta] starting tor"
tor --RunAsDaemon 1 --SocksPort 127.0.0.1:9050 --DataDirectory /var/lib/tor-ransomlook --Log "notice stdout"
for _ in $(seq 1 60); do
  if curl -fsS --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip -o /dev/null 2>/dev/null; then
    echo "[vendetta] tor is up"; break
  fi
  sleep 5
done

echo "[vendetta] starting cache"
poetry run run_backend --start

if [ "${BOOTSTRAP_FROM}" != "off" ]; then
  # Fills an empty group list from a public instance's open API (no key) so the
  # first scrape has something to visit. Groups already present are left alone.
  python /opt/vendetta/bootstrap_groups.py --from "${BOOTSTRAP_FROM}" || echo "[vendetta] bootstrap failed; continuing"
fi

echo "[vendetta] starting API on :8000 with ${WORKERS} workers"
( cd website && gunicorn -w "${WORKERS}" --timeout 300 -b 0.0.0.0:8000 web:app ) &
WEB_PID=$!

trap 'kill ${WEB_PID} 2>/dev/null; poetry run run_backend --stop || true; exit 0' TERM INT

while kill -0 "${WEB_PID}" 2>/dev/null; do
  start=$(date +%s)
  echo "[vendetta] scrape cycle at $(date -u +%FT%TZ)"
  timeout "$(( INTERVAL * 60 * 3 ))" poetry run scrape || echo "[vendetta] scrape exited non-zero"
  timeout 1800 poetry run parse || echo "[vendetta] parse exited non-zero"
  took=$(( $(date +%s) - start ))
  echo "[vendetta] cycle took ${took}s"
  sleep "$(( INTERVAL * 60 > took ? INTERVAL * 60 - took : 60 ))" &
  wait $! || true
done
