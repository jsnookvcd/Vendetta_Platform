"""CrowdStrike Falcon Alerts API v2 puller.

API client in the client's Falcon console with the Alerts: Read scope, OAuth2 client
credentials at {base}/oauth2/token. The base URL is the client's Falcon cloud and must
be one of the official API hosts.

Each page is GET /alerts/queries/alerts/v2 (composite ids, filtered with FQL on
updated_timestamp and sorted ascending) followed by POST /alerts/entities/alerts/v2
for the full alerts. The filter is on updated_timestamp rather than created_timestamp
so a status change (in progress, closed) is ingested too; the mapper's dedupe id
includes updated_timestamp, so each version is stored once.

Paging uses offset and limit. The queries endpoint caps offset at 10,000; a run stops
there and the next run continues from the cursor, which sorting ascending makes safe.
Whether queries v2 also offers an `after` token for deeper paging is not confirmed
here, so it is not used.
"""
from __future__ import annotations

from .. import ocsf
from . import ConnectorError, Puller, puller
from ._util import from_ms, https_base, json_body, z

DEFAULT_BASE = "https://api.crowdstrike.com"
HOSTS = {"api.crowdstrike.com", "api.us-2.crowdstrike.com", "api.eu-1.crowdstrike.com",
         "api.laggar.gcw.crowdstrike.com"}
LIMIT = 500
MAX_OFFSET = 10_000

SPEC = {
    "credentials": {"client_secret": "Falcon API client secret (scope Alerts: Read)"},
    "config": {"client_id": "Falcon API client id",
               "base_url": "Falcon API base URL for the client's cloud (default https://api.crowdstrike.com; "
                           "us-2, eu-1 and gov hosts are accepted)"},
}


@puller
class CrowdStrikeAlerts(Puller):
    source = "crowdstrike_alerts"
    spec = SPEC

    def token(self, base: str) -> str:
        self.need("client_id", where="config")
        self.need("client_secret")
        r = self.request("POST", f"{base}/oauth2/token", data={
            "client_id": str(self.config["client_id"]).strip(), "client_secret": self.credentials["client_secret"]})
        body = json_body(r, "Falcon")
        tok = body.get("access_token") if isinstance(body, dict) else None
        if not tok:
            raise ConnectorError("token exchange returned no access token")
        return tok

    def pages(self):
        base = https_base(self.config.get("base_url") or DEFAULT_BASE, hosts=HOSTS)
        headers = {"Authorization": f"Bearer {self.token(base)}", "Accept": "application/json"}
        since = self.since()
        newest = since
        offset = 0
        fql = f"updated_timestamp:>='{z(since, ms=True)}'"
        while offset < MAX_OFFSET:
            r = self.request("GET", f"{base}/alerts/queries/alerts/v2", headers=headers, params={
                "filter": fql, "sort": "updated_timestamp.asc", "limit": str(LIMIT), "offset": str(offset)})
            body = json_body(r, "Falcon")
            if not isinstance(body, dict):
                raise ConnectorError("Falcon returned an unexpected query response")
            ids = [i for i in body.get("resources") or [] if isinstance(i, str)]
            if not ids:
                return
            e = self.request("POST", f"{base}/alerts/entities/alerts/v2", headers=headers,
                             json={"composite_ids": ids})
            ebody = json_body(e, "Falcon")
            rows = (ebody.get("resources") if isinstance(ebody, dict) else None) or []
            for row in rows:
                ms = ocsf.to_epoch_ms(row.get("updated_timestamp")) if isinstance(row, dict) else None
                if ms is not None:
                    newest = max(newest, from_ms(ms))
            yield rows, {"since": newest.isoformat()}
            total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
            offset += len(ids)
            if not isinstance(total, int) or offset >= total:
                return
