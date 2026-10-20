"""Microsoft Defender XDR alerts puller (Microsoft Graph security alerts_v2).

The same app registration pattern as the Entra pullers, with the application
permission SecurityAlert.Read.All (admin consent) in the client's tenant.

GET https://graph.microsoft.com/v1.0/security/alerts_v2 filtered on
lastUpdateDateTime, so new alerts and status changes both arrive; the mapper's dedupe
id includes lastUpdateDateTime. The alerts_v2 list documents $filter, $top, $skip and
$count but not $orderby, so pages come in no guaranteed order. The cursor therefore
advances only when the last page of a run's window is ingested; a run that stops
early repeats its window next time and the duplicates are dropped.
"""
from __future__ import annotations

import datetime as dt

import httpx

from .. import ocsf
from . import ConnectorError, puller
from ._util import from_ms, json_body, same_host
from .microsoft_graph import GRAPH, _GraphPuller

SPEC = {
    "credentials": {"client_secret": "Client secret of the app registration in the client's tenant "
                                     "(application permission SecurityAlert.Read.All)"},
    "config": {"tenant_id": "Client's Entra tenant id (GUID)", "client_id": "Application (client) id"},
}


@puller
class DefenderAlerts(_GraphPuller):
    source = "defender_alerts"
    spec = SPEC
    path = "/security/alerts_v2"
    time_field = "lastUpdateDateTime"

    def pages(self):
        tok = self.token()
        headers = {"Authorization": f"Bearer {tok}"}
        since = self.since()
        start = (since - dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        url = f"{GRAPH}/v1.0{self.path}"
        params = {"$filter": f"{self.time_field} ge {start}", "$top": "500"}
        newest = since
        while url:
            r = self.request("GET", url, headers=headers, params=params)
            body = json_body(r, "graph.microsoft.com")
            if not isinstance(body, dict):
                raise ConnectorError("Graph returned an unexpected response")
            rows = body.get("value") or []
            for row in rows:
                ms = ocsf.to_epoch_ms(row.get(self.time_field)) if isinstance(row, dict) else None
                if ms is not None:
                    newest = max(newest, from_ms(ms))
            nxt = body.get("@odata.nextLink")
            if nxt:
                nxt = same_host(nxt, httpx.URL(GRAPH).host)
            yield rows, {"since": (newest if not nxt else since).isoformat()}
            url, params = (nxt, None) if nxt else (None, None)
