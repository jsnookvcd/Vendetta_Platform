"""Microsoft Graph pullers: Entra sign-ins and directory audits.

App registration in the client's tenant with application permissions
AuditLog.Read.All and Directory.Read.All (admin consent), client credentials flow.
Sign-in logs need Entra ID P1 or P2 in the client tenant.
"""
from __future__ import annotations

import datetime as dt

import httpx

from .. import ocsf
from . import ConnectorError, Puller, puller
from ._util import same_host

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"

SPEC = {
    "credentials": {"client_secret": "Client secret of the app registration in the client's tenant"},
    "config": {"tenant_id": "Client's Entra tenant id (GUID)", "client_id": "Application (client) id"},
}


class _GraphPuller(Puller):
    path = ""
    time_field = ""

    def token(self, scope: str = f"{GRAPH}/.default") -> str:
        self.need("tenant_id", "client_id", where="config")
        self.need("client_secret")
        tid = str(self.config["tenant_id"]).strip()
        if not all(ch.isalnum() or ch in "-." for ch in tid):
            raise ConnectorError("tenant_id is not a tenant id or domain")
        r = self.request("POST", f"{LOGIN}/{tid}/oauth2/v2.0/token", data={
            "grant_type": "client_credentials", "client_id": self.config["client_id"],
            "client_secret": self.credentials["client_secret"], "scope": scope})
        tok = (r.json() or {}).get("access_token")
        if not tok:
            raise ConnectorError("token exchange returned no access token")
        return tok

    def pages(self):
        tok = self.token()
        headers = {"Authorization": f"Bearer {tok}"}
        since = self.since()
        # Overlap the window by five minutes: Graph audit rows can land late, and the
        # pipeline drops the duplicates by record id.
        start = (since - dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        url = f"{GRAPH}/v1.0{self.path}"
        params = {"$filter": f"{self.time_field} ge {start}", "$top": "500", "$orderby": f"{self.time_field} asc"}
        newest = since
        while url:
            r = self.request("GET", url, headers=headers, params=params)
            body = r.json() or {}
            rows = body.get("value") or []
            for row in rows:
                ms = ocsf.to_epoch_ms(row.get(self.time_field))
                if ms is not None:
                    newest = max(newest, dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc))
            nxt = body.get("@odata.nextLink")
            if nxt:
                nxt = same_host(nxt, httpx.URL(GRAPH).host)  # https on graph.microsoft.com only
            url, params = (nxt, None) if nxt else (None, None)
            yield rows, {"since": newest.isoformat()}


@puller
class EntraSignins(_GraphPuller):
    source = "entra_signins"
    spec = SPEC
    path = "/auditLogs/signIns"
    time_field = "createdDateTime"


@puller
class EntraAudit(_GraphPuller):
    source = "entra_audit"
    spec = SPEC
    path = "/auditLogs/directoryAudits"
    time_field = "activityDateTime"
