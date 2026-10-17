"""ransomware.live PRO API client.

What was verified, and from where (Oct 17, 2026):

  The official spec at https://api-pro.ransomware.live/openapi.json and the docs
  page https://api-pro.ransomware.live/docs could not be read from the build
  sandbox (its egress proxy refuses the host with 403, and the docs page is a
  client-rendered Swagger UI). The JMousqueton/api.ransomware.live README
  documents only the old free API (/recentvictims, /groups, /group/<name>).
  The PRO facts below come from the sources that were readable:

  - https://www.ransomware.live/api : the PRO tier is free with an API key
    requested at https://my.ransomware.live, has no hard rate limit, applies a
    fair-use policy and quotes 500,000 calls a month; docs live at
    https://api-pro.ransomware.live/docs.
  - github.com/muchdogesec/ransomware2stix docs/README.md (curl examples with
    recorded responses against api-pro.ransomware.live):
      auth header   X-API-KEY: <key>
      GET /groups           {"groups": [{"group", "altname", "victims"}]}
                            The list carries no locations.
      GET /groups/{name}    {"client", "group", "description", "victims",
                             "firstseen", "lastseen", "locations": [{"fqdn",
                             "title", "slug", "available", "updated",
                             "lastscrape", "type"}], "tools", "ttps", "url"}
                            type is "DLS" for the leak site and "Chat" for the
                            negotiation portal.
      GET /victims/?group=x {"victims": [{"victim", "group", "discovered",
                             "attackdate", "website", "post_url", "country",
                             "activity", "description", "id", "permalink",
                             "screenshot", "infostealer", "press",
                             "duplicates", "extrainfos"}]}
  - github.com/Liberty91LTD/cti-skills tools/integrations/ransomwarelive.md:
      GET /victims/recent returns the last 100 claims as {"victims": [...]}
      (group_name is sometimes null in that endpoint), GET /validate returns
      {"status": "valid", "client": "<email>"}, and the free v2 tier is limited
      to one request per minute per endpoint.
  - github.com/franckferman/CassandraCTI sources/ransomware_live.py reads the
    same /victims/recent shape with the X-API-KEY header.
  - https://ransomware.live/changelog (2026-08-22): locations gained "captcha"
    and "seized" fields.

When the host can reach the spec, compare it with the fixtures under
tests/fixtures/ransomware_live_*.json and update both if anything differs.

Fair use, as this client enforces it: one call per endpoint per run (a client
instance caches every path it has fetched, so a second request for the same
path in a run is served from memory), a User-Agent naming this tool, and on 429
a wait that honours Retry-After before at most RETRIES_ON_429 more attempts.
The key is only ever sent in the header and never logged."""
from __future__ import annotations

import datetime as dt
import email.utils
import logging
import time
from typing import Any, Callable

import httpx

from . import fetch as fetch_mod
from .config import settings

log = logging.getLogger(__name__)

NOT_CONFIGURED = "not configured: needs a free PRO key from my.ransomware.live"
RETRIES_ON_429 = 2
MAX_RETRY_AFTER_SECONDS = 300
DEFAULT_RETRY_AFTER_SECONDS = 60

RECENT_VICTIMS = "/victims/recent"
GROUPS = "/groups"


class RansomwareLiveError(Exception):
    """Any failure talking to the PRO API. The message never carries the key."""


class NotConfigured(RansomwareLiveError):
    pass


class AuthError(RansomwareLiveError):
    pass


class RateLimited(RansomwareLiveError):
    pass


class SchemaDrift(RansomwareLiveError):
    pass


def configured() -> bool:
    return bool((settings.ransomware_live_api_key or "").strip())


def base_url() -> str:
    return (settings.ransomware_live_base or "https://api-pro.ransomware.live").rstrip("/")


def headers() -> dict:
    if not configured():
        return {}
    return {
        settings.ransomware_live_api_header: settings.ransomware_live_api_key.strip(),
        "Accept": "application/json",
        "User-Agent": settings.ransomware_live_user_agent,
    }


def _retry_after_seconds(value: str | None) -> float:
    if not value:
        return DEFAULT_RETRY_AFTER_SECONDS
    value = value.strip()
    try:
        secs = float(value)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return DEFAULT_RETRY_AFTER_SECONDS
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        secs = (when - dt.datetime.now(dt.timezone.utc)).total_seconds()
    return max(0.0, min(secs, MAX_RETRY_AFTER_SECONDS))


class Client:
    """One instance per collector run. `sleep` is injectable so tests never wait."""

    def __init__(self, sleep: Callable[[float], None] = time.sleep):
        if not configured():
            raise NotConfigured(NOT_CONFIGURED)
        self._sleep = sleep
        self._cache: dict[str, Any] = {}
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        if path in self._cache:
            return self._cache[path]
        url = f"{base_url()}{path}"
        attempt = 0
        while True:
            self.calls.append(path)
            try:
                with fetch_mod._client(False) as c:
                    r = c.get(url, headers=headers())
            except httpx.HTTPError as e:
                raise RansomwareLiveError(f"{path}: {type(e).__name__}: {e}") from e
            if r.status_code == 429:
                wait = _retry_after_seconds(r.headers.get("retry-after"))
                if attempt >= RETRIES_ON_429:
                    raise RateLimited(f"{path}: HTTP 429 rate limited after {attempt + 1} attempts "
                                      f"(Retry-After {r.headers.get('retry-after') or 'absent'})")
                attempt += 1
                log.warning("ransomware.live %s rate limited; waiting %.0fs (Retry-After)", path, wait)
                self._sleep(wait)
                continue
            if r.status_code in (401, 403):
                raise AuthError(f"{path}: HTTP {r.status_code}: the PRO key was refused; check "
                                "RANSOMWARE_LIVE_API_KEY at my.ransomware.live")
            if r.status_code >= 400:
                raise RansomwareLiveError(f"{path}: HTTP {r.status_code}")
            try:
                data = r.json()
            except ValueError as e:
                raise SchemaDrift(f"{path}: response is not JSON") from e
            self._cache[path] = data
            return data

    # ------------------------------------------------------------ typed endpoints
    def recent_victims(self) -> list[dict]:
        data = self.get(RECENT_VICTIMS)
        rows = data.get("victims") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise SchemaDrift(f"{RECENT_VICTIMS}: expected a 'victims' list, got keys "
                              f"{sorted(data)[:8] if isinstance(data, dict) else type(data).__name__}")
        rows = [v for v in rows if isinstance(v, dict)]
        if rows and not any((v.get("victim") or v.get("post_title")) for v in rows):
            raise SchemaDrift(f"{RECENT_VICTIMS}: no row carries a 'victim' field; the schema changed")
        return rows

    def groups(self) -> list[dict]:
        data = self.get(GROUPS)
        rows = data.get("groups") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise SchemaDrift(f"{GROUPS}: expected a 'groups' list")
        out = []
        for g in rows:
            if isinstance(g, dict) and (g.get("group") or g.get("name")):
                out.append({**g, "group": g.get("group") or g.get("name")})
        if rows and not out:
            raise SchemaDrift(f"{GROUPS}: no row carries a 'group' field; the schema changed")
        return out

    def group(self, name: str) -> dict:
        path = f"{GROUPS}/{name.strip().lower()}"
        data = self.get(path)
        if not isinstance(data, dict):
            raise SchemaDrift(f"{path}: expected an object")
        locs = data.get("locations")
        if locs is not None and not isinstance(locs, list):
            raise SchemaDrift(f"{path}: 'locations' is not a list")
        return data


def victim_name(v: dict) -> str:
    return (v.get("victim") or v.get("post_title") or v.get("title") or "").strip()


def victim_group(v: dict) -> str:
    return (v.get("group") or v.get("group_name") or "").strip()


def victim_target_url(v: dict) -> str:
    """The original leak post when the feed gives one."""
    for k in ("post_url", "claim_url"):
        u = (v.get(k) or "").strip()
        if u.startswith(("http://", "https://")):
            return u
    return ""
