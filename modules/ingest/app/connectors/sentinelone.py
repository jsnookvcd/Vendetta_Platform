"""SentinelOne Management API v2.1 threats puller.

A service user API token with the Viewer role (or a custom role that can read
threats) at the account or site scope that covers the client. The base URL is the
client's management console, https://<tenant>.sentinelone.net.

GET /web/api/v2.1/threats with createdAt__gt from the cursor, sorted by createdAt
ascending, paged with pagination.nextCursor. The cursor stored after each page is
the newest createdAt seen, so a run that stops early resumes after the last page it
ingested. Threats changed after creation (mitigated, resolved) are not re-read by
this filter; a later wave can add an updatedAt__gt pass if the SOC wants status
changes from SentinelOne.
"""
from __future__ import annotations

from .. import ocsf
from . import ConnectorError, Puller, puller
from ._util import from_ms, https_base, json_body, z

LIMIT = 1000

SPEC = {
    "credentials": {"api_token": "SentinelOne service user API token"},
    "config": {"base_url": "Management console URL, https://<tenant>.sentinelone.net",
               "account_ids": "Optional comma-separated account ids to limit the pull",
               "site_ids": "Optional comma-separated site ids to limit the pull"},
}


def _created(row: dict):
    ti = row.get("threatInfo") if isinstance(row.get("threatInfo"), dict) else {}
    return ti.get("createdAt") or row.get("createdAt")


def _ids(v) -> str | None:
    s = ",".join(p.strip() for p in str(v or "").split(",") if p.strip())
    if s and not all(ch.isdigit() or ch == "," for ch in s):
        raise ConnectorError("account_ids and site_ids must be numeric ids")
    return s or None


@puller
class SentinelOneThreats(Puller):
    source = "sentinelone_threats"
    spec = SPEC

    def pages(self):
        base = https_base(self.config.get("base_url"), suffixes=(".sentinelone.net",))
        self.need("api_token")
        headers = {"Authorization": f"ApiToken {self.credentials['api_token']}", "Accept": "application/json"}
        since = self.since()
        newest = since
        params = {"createdAt__gt": z(since, ms=True), "sortBy": "createdAt", "sortOrder": "asc", "limit": str(LIMIT)}
        for key in ("account_ids", "site_ids"):
            ids = _ids(self.config.get(key))
            if ids:
                params["accountIds" if key == "account_ids" else "siteIds"] = ids
        url = f"{base}/web/api/v2.1/threats"
        while True:
            r = self.request("GET", url, headers=headers, params=params)
            body = json_body(r, "SentinelOne")
            if not isinstance(body, dict):
                raise ConnectorError("SentinelOne returned an unexpected response")
            rows = body.get("data") or []
            for row in rows:
                ms = ocsf.to_epoch_ms(_created(row)) if isinstance(row, dict) else None
                if ms is not None:
                    newest = max(newest, from_ms(ms))
            nxt = (body.get("pagination") or {}).get("nextCursor")
            if rows:
                yield rows, {"since": newest.isoformat()}
            if not nxt or not rows:
                return
            params = {**params, "cursor": str(nxt)}
