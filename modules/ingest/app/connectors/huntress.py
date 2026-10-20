"""Huntress incident reports puller.

An API key and secret generated in the Huntress portal (API Credentials), sent as
HTTP basic auth to https://api.huntress.io. Pages are GET /v1/incident_reports with
limit and page_token; the response's pagination object gives next_page_token (and
next_page_url, which is checked to stay on api.huntress.io).

The time filter `updated_at_min` follows the v1 reference as known in 2026 and should
be confirmed against a live account; rows older than the cursor are also dropped here
in case the filter is ignored. The response order is not documented, so the cursor
advances only on the last page.
"""
from __future__ import annotations

from .. import ocsf
from . import ConnectorError, Puller, puller
from ._util import from_ms, json_body, same_host, z

API = "https://api.huntress.io"
HOST = "api.huntress.io"
LIMIT = 500

SPEC = {
    "credentials": {"api_key": "Huntress API key", "api_secret": "Huntress API secret"},
    "config": {"organization_id": "Optional Huntress organization id to limit the pull (numeric)"},
}


def _updated(row: dict):
    return row.get("updated_at") or row.get("status_updated_at") or row.get("sent_at")


@puller
class HuntressIncidents(Puller):
    source = "huntress_incidents"
    spec = SPEC

    def pages(self):
        self.need("api_key", "api_secret")
        org = str(self.config.get("organization_id") or "").strip()
        if org and not org.isdigit():
            raise ConnectorError("organization_id must be a numeric Huntress organization id")
        auth = (str(self.credentials["api_key"]), str(self.credentials["api_secret"]))
        since = self.since()
        newest = since
        since_ms = int(since.timestamp() * 1000)
        params = {"limit": str(LIMIT), "updated_at_min": z(since)}
        if org:
            params["organization_id"] = org
        url = f"{API}/v1/incident_reports"
        while True:
            r = self.request("GET", url, auth=auth, params=params, headers={"Accept": "application/json"})
            body = json_body(r, HOST)
            if not isinstance(body, dict):
                raise ConnectorError("Huntress returned an unexpected response")
            rows = []
            for row in body.get("incident_reports") or []:
                ms = ocsf.to_epoch_ms(_updated(row)) if isinstance(row, dict) else None
                if ms is not None and ms < since_ms:
                    continue
                if ms is not None:
                    newest = max(newest, from_ms(ms))
                rows.append(row)
            pag = body.get("pagination") or {}
            token = pag.get("next_page_token")
            if pag.get("next_page_url"):
                same_host(str(pag["next_page_url"]), HOST)
            yield rows, {"since": (newest if not token else since).isoformat()}
            if not token:
                return
            params = {**params, "page_token": str(token)}
