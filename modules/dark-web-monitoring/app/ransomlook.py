"""RansomLook API client: the free victim feed and onion location source.

RansomLook (github.com/RansomLook/RansomLook) is an open source leak-site
monitor descended from ransomwatch. It scrapes several hundred group and market
sites over Tor with maintained per-group parsers and serves what it collects
through a REST API. Two ways to use it, chosen by RANSOMLOOK_URL:

  https://www.ransomlook.io   the public instance (default). No key. Its data,
                              API responses included, is published under
                              CC BY 4.0, so commercial use is allowed with
                              credit; every item and source this module stores
                              from it carries that attribution in meta.
  http://ransomlook:8000      Vendetta's own instance, the sidecar under
                              infra/ransomlook/, which scrapes leak sites from
                              this host through its own Tor and owes nothing to
                              any third-party service.

RansomLook's code is GPL. This module never imports or copies it: it only reads
the instance's HTTP API, so the sidecar stays a separate program.

Endpoints used, read from website/web/api/genericapi.py and statsapi.py at
RansomLook commit of Oct 21, 2026:

  GET /api/last/{days}     posts discovered in the last N days, newest first:
                           [{"post_title", "discovered", "description",
                             "website", "link", "screen", "group_name"}]
                           "discovered" is "YYYY-MM-DD HH:MM:SS.ffffff" (UTC,
                           naive); "screen" on list endpoints is a path, never
                           image data.
  GET /api/hot/{days}      {"days", "from_date", "total_posts",
                            "rows": [{"group", "count", "last_post"}]}
  GET /api/group/{name}    [group, posts]. group has "meta", "locations":
                           [{"slug", "fqdn", "title", "version", "available",
                             "updated", "lastscrape", "fs", "chat", "admin",
                             "screen", "source"}]. On a location, screen and
                           source are base64 image and HTML when present, so the
                           body can be large: reads are streamed under
                           RANSOMLOOK_MAX_BYTES and an oversized group is
                           skipped with a reason.

Fair use: one call per path per run (a client instance caches what it fetched),
a User-Agent naming this tool, and on 429 a wait that honours Retry-After before
at most RETRIES_ON_429 more attempts. RANSOMLOOK_URL is operator configuration,
so requests go out through the plain HTTP client rather than the fetch guard;
that is what lets the sidecar's internal address work."""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx

from . import fetch as fetch_mod
from . import ransomware_live as rl
from .config import settings

log = logging.getLogger(__name__)

PUBLIC_URL = "https://www.ransomlook.io"
ATTRIBUTION = "RansomLook (ransomlook.io), CC BY 4.0"
LICENSE = "CC-BY-4.0"
RETRIES_ON_429 = 2
NOT_CONFIGURED = "turned off (RANSOMLOOK_ENABLED=false)"


# Subclasses of the ransomware.live errors so onion seeding handles either
# provider with the same except clauses.
class RansomLookError(rl.RansomwareLiveError):
    pass


class RateLimited(RansomLookError, rl.RateLimited):
    pass


class AuthError(RansomLookError, rl.AuthError):
    pass


class SchemaDrift(RansomLookError, rl.SchemaDrift):
    pass


class TooLarge(RansomLookError):
    pass


def configured() -> bool:
    return bool(settings.ransomlook_enabled and base_url())


def base_url() -> str:
    return (settings.ransomlook_url or "").strip().rstrip("/")


def is_public() -> bool:
    return base_url().lower().rstrip("/") in (PUBLIC_URL, "https://ransomlook.io")


def label() -> str:
    """Provider name recorded on sources and items. The sidecar is named apart
    from the public instance so the record shows where collection happened."""
    return "ransomlook.io" if is_public() else "ransomlook (self-hosted)"


def headers() -> dict:
    h = {"Accept": "application/json", "User-Agent": settings.ransomware_live_user_agent}
    if settings.ransomlook_api_key:
        h["Authorization"] = settings.ransomlook_api_key
    return h


def provenance() -> dict:
    return {"provider": label(), "attribution": ATTRIBUTION, "license": LICENSE, "instance": base_url()}


class Client:
    """One instance per collector run. `sleep` is injectable so tests never wait."""

    def __init__(self, sleep: Callable[[float], None] = time.sleep, max_bytes: int | None = None):
        if not configured():
            raise rl.NotConfigured(NOT_CONFIGURED)
        self._sleep = sleep
        self._cache: dict[str, Any] = {}
        self._max = max_bytes or settings.ransomlook_max_bytes
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        if path in self._cache:
            return self._cache[path]
        url = f"{base_url()}{path}"
        attempt = 0
        while True:
            self.calls.append(path)
            try:
                with fetch_mod._client(False, settings.ransomlook_timeout) as c:
                    with c.stream("GET", url, headers=headers()) as r:
                        status = r.status_code
                        retry_after = r.headers.get("retry-after")
                        body = bytearray()
                        if status < 400:
                            for chunk in r.iter_bytes():
                                body.extend(chunk)
                                if len(body) > self._max:
                                    raise TooLarge(f"{path}: response larger than {self._max} bytes")
            except httpx.HTTPError as e:
                raise RansomLookError(f"{path}: {type(e).__name__}: {e}") from e
            if status == 429:
                wait = rl._retry_after_seconds(retry_after)
                if attempt >= RETRIES_ON_429:
                    raise RateLimited(f"{path}: HTTP 429 rate limited after {attempt + 1} attempts")
                attempt += 1
                log.warning("ransomlook %s rate limited; waiting %.0fs", path, wait)
                self._sleep(wait)
                continue
            if status in (401, 403):
                raise AuthError(f"{path}: HTTP {status}: the instance refused the request")
            if status >= 400:
                raise RansomLookError(f"{path}: HTTP {status}")
            try:
                data = json.loads(bytes(body))
            except ValueError as e:
                raise SchemaDrift(f"{path}: response is not JSON") from e
            self._cache[path] = data
            return data

    # ------------------------------------------------------------ typed endpoints
    def last_posts(self, days: int) -> list[dict]:
        path = f"/api/last/{max(1, int(days))}"
        data = self.get(path)
        if not isinstance(data, list):
            raise SchemaDrift(f"{path}: expected a list of posts")
        rows = [p for p in data if isinstance(p, dict)]
        if rows and not any(p.get("post_title") for p in rows):
            raise SchemaDrift(f"{path}: no row carries 'post_title'; the schema changed")
        return rows

    def groups(self, days: int = 365) -> list[dict]:
        """Groups that posted in the last `days`, in the shape onion seeding
        expects from ransomware.live: {"group", "victims", "lastseen"}."""
        path = f"/api/hot/{max(1, min(int(days), 365))}"
        data = self.get(path)
        rows = data.get("rows") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise SchemaDrift(f"{path}: expected an object with a 'rows' list")
        out = []
        for g in rows:
            if isinstance(g, dict) and g.get("group"):
                out.append({"group": str(g["group"]), "victims": int(g.get("count") or 0),
                            "lastseen": g.get("last_post")})
        if rows and not out:
            raise SchemaDrift(f"{path}: no row carries 'group'; the schema changed")
        return out

    def group(self, name: str) -> dict:
        """Group detail in the ransomware.live shape: {"group", "lastseen",
        "locations": [{"fqdn", "slug", "available", "updated", "lastscrape",
        "type"}]}. type is "chat", "admin" or "fs" for those portals so seeding
        skips them, "" for the leak site. Base64 screen and source are dropped."""
        path = f"/api/group/{quote(name.strip().lower(), safe='')}"
        data = self.get(path)
        if not (isinstance(data, list) and data and isinstance(data[0], dict)):
            raise SchemaDrift(f"{path}: expected [group, posts]")
        grp = data[0]
        posts = data[1] if len(data) > 1 and isinstance(data[1], list) else []
        locs = grp.get("locations")
        if locs is not None and not isinstance(locs, list):
            raise SchemaDrift(f"{path}: 'locations' is not a list")
        out_locs = []
        for loc in locs or []:
            if not isinstance(loc, dict):
                continue
            slug = str(loc.get("slug") or "").strip()
            fqdn = str(loc.get("fqdn") or "").strip().lower() or fetch_host(slug)
            kind = "chat" if loc.get("chat") else "admin" if loc.get("admin") else "fs" if loc.get("fs") else ""
            out_locs.append({"fqdn": fqdn, "slug": slug, "title": loc.get("title") or "",
                             "available": loc.get("available"), "updated": loc.get("updated"),
                             "lastscrape": loc.get("lastscrape"), "type": kind})
        newest = max((str(p.get("discovered") or "") for p in posts if isinstance(p, dict)), default="")
        return {"group": name.strip(), "lastseen": newest or None, "locations": out_locs}


def fetch_host(slug: str) -> str:
    if not slug:
        return ""
    try:
        return (httpx.URL(slug if "://" in slug else f"http://{slug}").host or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def post_url(p: dict) -> str:
    """The leak post itself, when the instance recorded one."""
    u = str(p.get("link") or "").strip()
    return u if u.startswith(("http://", "https://")) else ""
