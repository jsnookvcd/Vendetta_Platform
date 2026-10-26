# Vendetta's own RansomLook instance

RansomLook (github.com/RansomLook/RansomLook) is an open source leak-site monitor that scrapes several hundred ransomware group and market sites over Tor with maintained per-group parsers. By default the dark web module reads the public instance at ransomlook.io. This directory runs a private instance on the dark web host instead, so victim collection comes from Vendetta's own Tor circuits and does not depend on any third-party service staying up or free.

## How it fits

The sidecar is a compose service in the dark web stack, behind the `ransomlook` profile, on the stack's internal network only. It has no host port and no ALB route. The worker reads it at `http://ransomlook:8000` with the same client it uses for the public instance (`app/ransomlook.py`), so the victim feed, onion seeding and priority ranking work unchanged. Sources and items it produces are labelled `ransomlook (self-hosted)`.

The container runs four things: its own Tor (RansomLook expects SOCKS on 127.0.0.1:9050), the Redis cache RansomLook keeps its data in, the RansomLook API under gunicorn with two workers, and a scrape and parse cycle every `SCRAPE_INTERVAL_MINUTES` (60 by default).

On first start the group list is empty. `bootstrap_groups.py` fills it from the public instance's open endpoints (`/api/hot/365`, then `/api/group/<name>`), registering each group's onion leak-site locations through RansomLook's own `adder()`. Groups already present are left alone, so a restart never overwrites what this instance has learned. Set `RANSOMLOOK_BOOTSTRAP_FROM=off` to skip it.

## Turn it on

Add three parameters under `/vendetta/dark-web-monitoring/` in SSM, then redeploy the module:

```
COMPOSE_PROFILES=ransomlook
RANSOMLOOK_URL=http://ransomlook:8000
RANSOMLOOK_MEM_LIMIT=3g            # optional
```

```
infra/redeploy.sh dark-web-monitoring
```

The first build takes several minutes (Playwright and Chromium). The first scrape cycle starts once Tor is up and can take an hour or more across a few hundred sites. Until it finishes, `/api/last/2` returns few posts and the RansomLook victims connector shows few new items; that is expected.

To go back to the public instance, remove `RANSOMLOOK_URL` (or set it to `https://www.ransomlook.io`) and `COMPOSE_PROFILES`, then redeploy.

## Licensing

RansomLook's code is GPL-3.0 (its website states AGPL-3.0 for the project). The image builds it unmodified from upstream at the commit pinned in the `Dockerfile` and serves it only on the internal network. The dark web module never imports or copies RansomLook code; it reads the API over HTTP, so it remains a separate program. `bootstrap_groups.py` runs inside the RansomLook environment against RansomLook's code and is licensed GPL-3.0-or-later for that reason. If Vendetta ever exposes this instance's web UI to people outside the company, the AGPL obligation to offer them the source would apply; keep it internal.

Data from the public instance (used by the bootstrap) is published under CC BY 4.0 and is credited in the module README.

## Resource notes

Chromium captures run two at a time (`thread: 2` in `generic.json`). Expect 1 to 2 GB of memory during a cycle and steady growth of the `ransomlook-source` volume, which holds page captures. The host's nightly backup covers the module database, not these volumes; the sidecar can always rebuild its state by scraping again.

## Not yet verified

The build sandbox cannot pull from Docker Hub, so the image has not been built here. The `ransomlook sidecar` GitHub workflow builds it on amd64 and confirms the three API paths answer. The production host is arm64 (t4g.large); Playwright publishes arm64 Chromium, but RansomLook's Python dependencies have not been built on arm64 yet. Watch the first `redeploy.sh` output.

To bump RansomLook, change `RANSOMLOOK_REF` in the `Dockerfile` after reading the upstream diff, and confirm the API shapes documented at the top of `app/ransomlook.py` still hold.
