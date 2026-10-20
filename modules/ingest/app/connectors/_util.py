"""Helpers shared by the wave 1 pullers: URL policy and time formatting.

The module name starts with an underscore so the connector loader skips it.
"""
from __future__ import annotations

import datetime as dt
import re

import httpx

from . import ConnectorError

_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")


def https_base(value: str, *, hosts: set[str] | None = None, suffixes: tuple[str, ...] = (),
               what: str = "base_url") -> str:
    """Validate an operator-set base URL and return it as https://host.

    The URL must be https, carry no credentials, port, query or path beyond "/",
    and its host must be one of `hosts` or end with one of `suffixes`."""
    raw = str(value or "").strip()
    if not raw:
        raise ConnectorError(f"missing config: {what}")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        u = httpx.URL(raw)
    except Exception:  # noqa: BLE001 - httpx raises several types for bad URLs
        raise ConnectorError(f"{what} is not a valid URL") from None
    host = (u.host or "").lower()
    if u.scheme != "https":
        raise ConnectorError(f"{what} must use https")
    if u.userinfo or u.port not in (None, 443) or u.query or u.path not in ("", "/") or u.fragment:
        raise ConnectorError(f"{what} must be a bare https host")
    if not _HOST.match(host):
        raise ConnectorError(f"{what} host is not a DNS name")
    ok = (hosts is not None and host in hosts) or (suffixes and host.endswith(suffixes))
    if not ok:
        raise ConnectorError(f"{what} is not an allowed host for this vendor")
    return f"https://{host}"


def same_host(url: str, host: str, what: str = "next link") -> str:
    """Refuse a URL taken from a response unless it is https on the expected host."""
    try:
        u = httpx.URL(url)
    except Exception:  # noqa: BLE001
        raise ConnectorError(f"vendor returned an invalid {what}") from None
    if u.scheme != "https" or (u.host or "").lower() != host.lower():
        raise ConnectorError(f"vendor returned a {what} to another host")
    return str(u)


def z(d: dt.datetime, ms: bool = False) -> str:
    """UTC ISO 8601 with a Z suffix, seconds or milliseconds."""
    d = d.astimezone(dt.timezone.utc)
    if ms:
        return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_dt(v) -> dt.datetime | None:
    if not v:
        return None
    try:
        d = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def from_ms(ms: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc)


def json_body(r: httpx.Response, host: str):
    try:
        return r.json()
    except ValueError:
        raise ConnectorError(f"{host} returned a body that is not JSON") from None
