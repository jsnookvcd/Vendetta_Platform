"""Office 365 Management Activity API puller (the unified audit log).

App registration in the client's tenant with the Office 365 Management APIs
application permission ActivityFeed.Read (admin consent). The token is requested
with scope https://manage.office.com/.default through the same client credentials
flow as the Graph pullers. Commercial cloud only; GCC High and DoD use other hosts.

For each content type, the puller walks time windows of at most `window_minutes`
(default 60, never more than the API's 24 hour limit) from the cursor to now:

1. GET /api/v1.0/{tenant}/activity/feed/subscriptions/content?contentType=...
   &startTime=...&endTime=... lists the content blobs created in the window, paged
   with the NextPageUri response header;
2. each blob's contentUri is fetched and its JSON array of audit records ingested.

A listing page and its blobs are one page for the runner. The cursor keeps one
position per content type and moves to a window's end only once all of that window
is ingested. Empty windows advance the cursor without spending a page. The API keeps
content for seven days, so a cursor older than that restarts at the oldest window
still available.

On the first run the puller lists the tenant's subscriptions and starts the ones
that are missing (POST subscriptions/start); `start_subscriptions=false` turns that off.
"""
from __future__ import annotations

import datetime as dt

from . import FIRST_LOOKBACK, ConnectorError, puller
from ._util import json_body, parse_dt, same_host
from .microsoft_graph import _GraphPuller

MANAGE = "https://manage.office.com"
HOST = "manage.office.com"
DEFAULT_TYPES = ("Audit.Exchange", "Audit.SharePoint", "Audit.General")
ALLOWED_TYPES = {"Audit.Exchange", "Audit.SharePoint", "Audit.General", "Audit.AzureActiveDirectory", "DLP.All"}
RETENTION = dt.timedelta(days=7)

SPEC = {
    "credentials": {"client_secret": "Client secret of the app registration in the client's tenant "
                                     "(Office 365 Management APIs: ActivityFeed.Read)"},
    "config": {"tenant_id": "Client's Entra tenant id (GUID)", "client_id": "Application (client) id",
               "contentTypes": "Comma-separated content types (default Audit.Exchange,Audit.SharePoint,"
                               "Audit.General; Audit.AzureActiveDirectory and DLP.All are also accepted)",
               "window_minutes": "Listing window in minutes, 5 to 1440 (default 60)",
               "start_subscriptions": "true (default) to start missing subscriptions on the first run",
               "publisher_id": "Optional PublisherIdentifier (Vendetta's tenant GUID) for API quota"},
}


def _fmt(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


@puller
class M365Audit(_GraphPuller):
    source = "m365_audit"
    spec = SPEC

    def content_types(self) -> list[str]:
        raw = self.config.get("contentTypes") or ",".join(DEFAULT_TYPES)
        types = [t.strip() for t in str(raw).split(",") if t.strip()]
        bad = [t for t in types if t not in ALLOWED_TYPES]
        if bad or not types:
            raise ConnectorError("contentTypes has an unknown content type")
        return list(dict.fromkeys(types))

    def window(self) -> dt.timedelta:
        try:
            m = int(self.config.get("window_minutes") or 60)
        except (TypeError, ValueError):
            raise ConnectorError("window_minutes must be a number") from None
        if not 5 <= m <= 1440:
            raise ConnectorError("window_minutes must be between 5 and 1440")
        return dt.timedelta(minutes=m)

    def _ensure_subscriptions(self, base: str, headers: dict, params: dict, types: list[str]) -> None:
        r = self.request("GET", f"{base}/subscriptions/list", headers=headers, params=params)
        body = json_body(r, HOST)
        enabled = {str(s.get("contentType")) for s in body or [] if isinstance(s, dict)
                   and str(s.get("status") or "").lower() == "enabled"} if isinstance(body, list) else set()
        for t in types:
            if t not in enabled:
                self.request("POST", f"{base}/subscriptions/start", headers=headers,
                             params={**params, "contentType": t})

    def pages(self):
        types = self.content_types()
        step = self.window()
        tok = self.token(scope=f"{MANAGE}/.default")  # validates tenant_id, client_id, client_secret
        tid = str(self.config["tenant_id"]).strip()
        base = f"{MANAGE}/api/v1.0/{tid}/activity/feed"
        headers = {"Authorization": f"Bearer {tok}"}
        pub = str(self.config.get("publisher_id") or "").strip()
        if pub and not all(ch.isalnum() or ch == "-" for ch in pub):
            raise ConnectorError("publisher_id is not a tenant GUID")
        qp = {"PublisherIdentifier": pub} if pub else {}

        state = self.cursor.get("since") if isinstance(self.cursor.get("since"), dict) else {}
        state = {k: v for k, v in state.items() if k in types}
        subscribed = bool(self.cursor.get("subscribed"))
        if not subscribed and str(self.config.get("start_subscriptions", "true")).lower() != "false":
            self._ensure_subscriptions(base, headers, qp, types)
        subscribed = True

        def cursor() -> dict:
            return {"since": dict(state), "subscribed": subscribed}

        floor = self.now - RETENTION + dt.timedelta(minutes=10)
        pending = False  # cursor moved without a yield
        for ct in types:
            start = parse_dt(state.get(ct)) or (self.now - FIRST_LOOKBACK)
            start = max(start, floor)
            while start < self.now:
                end = min(start + step, self.now)
                url: str | None = f"{base}/subscriptions/content"
                params: dict | None = {**qp, "contentType": ct, "startTime": _fmt(start), "endTime": _fmt(end)}
                while url:
                    r = self.request("GET", url, headers=headers, params=params)
                    blobs = json_body(r, HOST)
                    if not isinstance(blobs, list):
                        raise ConnectorError("Management Activity API returned an unexpected listing")
                    records: list = []
                    for b in blobs:
                        uri = b.get("contentUri") if isinstance(b, dict) else None
                        if not uri:
                            continue
                        rr = self.request("GET", same_host(str(uri), HOST, "content URI"), headers=headers)
                        rows = json_body(rr, HOST)
                        if not isinstance(rows, list):
                            raise ConnectorError("Management Activity API returned a content blob that is not a list")
                        records.extend(rows)
                    nxt = r.headers.get("NextPageUri")
                    if not nxt:
                        state[ct] = end.isoformat()
                    if records:
                        yield records, cursor()
                        pending = False
                    elif not nxt:
                        pending = True
                    url, params = (same_host(nxt, HOST, "next page URI"), None) if nxt else (None, None)
                start = end
        if pending or not self.cursor.get("subscribed"):
            yield [], cursor()
