"""Shared connector plumbing.

Every connector normalizes into the same two shapes so the sync engine and the UI
never care which vendor a record came from:

Device: {external_id, hostname, platform, status, agent_version, last_seen, link, raw}
  status: online | offline | isolated | isolating | unknown
Alert:  {external_id, kind, severity, title, detail, tool_status, occurred_at,
         link, resolved, raw}
  severity: info | low | medium | high | critical

Connectors raise ConnectorError with a readable message; callers turn that into a
failed ActionLog row or a sync warning rather than a stack trace."""
from __future__ import annotations

import datetime as dt

import httpx


class ConnectorError(Exception):
    pass


def make_client(base_url: str, headers: dict | None = None, transport: httpx.BaseTransport | None = None,
                auth: tuple[str, str] | None = None, timeout: float = 30.0) -> httpx.Client:
    return httpx.Client(base_url=base_url, headers=headers or {}, transport=transport,
                        auth=auth, timeout=timeout, follow_redirects=False)


def parse_dt(value) -> dt.datetime | None:
    """Vendor timestamps: ISO with or without Z or offset, or epoch seconds/ms."""
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        if value > 1e12:  # milliseconds
            value = value / 1000.0
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def recent(ts: dt.datetime | None, minutes: int) -> bool:
    return bool(ts) and (dt.datetime.now(dt.timezone.utc) - ts) < dt.timedelta(minutes=minutes)
