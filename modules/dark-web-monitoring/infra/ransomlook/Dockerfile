# Vendetta's own RansomLook instance: a separate program, built unmodified from
# the upstream source at a pinned commit. RansomLook is GPL-3.0; nothing here is
# linked into the dark web module, which only reads this container's HTTP API.
# See README.md in this directory.
FROM ubuntu:24.04

ARG RANSOMLOOK_REPO=https://github.com/RansomLook/RansomLook.git
# Upstream main on Oct 21, 2026. Bump deliberately, after reading the diff.
ARG RANSOMLOOK_REF=ef9f17b025692863c9b6cb41678782ffb99ff95a

ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 LANG=C.UTF-8 TZ=Etc/UTC \
    POETRY_VIRTUALENVS_IN_PROJECT=true POETRY_NO_INTERACTION=1 \
    RANSOMLOOK_HOME=/opt/RansomLook PATH=/opt/RansomLook/.venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git curl tor redis-server python3 python3-dev python3-venv python3-pip \
        build-essential pkg-config libffi-dev libssl-dev libjpeg-dev zlib1g-dev \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libcairo2 tini \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir "poetry>=2.1,<3"

RUN git clone "$RANSOMLOOK_REPO" /opt/RansomLook \
    && git -C /opt/RansomLook checkout --detach "$RANSOMLOOK_REF" \
    && git -C /opt/RansomLook log -1 --format='RansomLook %H %cd' > /opt/ransomlook-version

WORKDIR /opt/RansomLook
# run_redis.sh looks for ../../redis/src/redis-server when no Valkey build sits
# beside the checkout; point it at the distribution's server.
RUN mkdir -p /opt/redis/src && ln -s /usr/bin/redis-server /opt/redis/src/redis-server \
    && echo "RANSOMLOOK_HOME='/opt/RansomLook'" > .env \
    && poetry install --only main \
    && poetry run playwright install --with-deps chromium \
    && (poetry run tools/3rdparty.py || echo "3rd-party web assets skipped; the API does not need them") \
    && cp -a cache /opt/ransomlook-cache-defaults \
    && rm -rf /root/.cache/pip /root/.cache/pypoetry/cache

COPY generic.json /opt/RansomLook/config/generic.json
COPY entrypoint.sh /usr/local/bin/vendetta-ransomlook
COPY bootstrap_groups.py /opt/vendetta/bootstrap_groups.py
RUN chmod +x /usr/local/bin/vendetta-ransomlook

EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=10s --start-period=180s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/api/groups -o /dev/null || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vendetta-ransomlook"]
