"""Microsoft 365 / Entra ID identity-signal connector.

Pulls identity risk from Microsoft Graph Identity Protection and normalizes it into
the shared Alert shape, so a risky sign-in or a confirmed-compromised account shows up
in the managed-services console and portal next to EDR and backup alerts.

Auth is app-only (client credentials) with a multi-tenant Entra app consented in each
client tenant. The client's tenant id is its per-client ref, so one app addresses every
client's slice. Required Graph application permissions: IdentityRiskEvent.Read.All (risk
detections) and, optionally, SecurityEvents.Read.All. Read-only: this connector has no
actions, so nothing here writes to a client tenant."""
from __future__ import annotations

import logging

import httpx

from .. import creds
from .base import ConnectorError, make_client, parse_dt

log = logging.getLogger(__name__)

# Graph riskLevel -> shared severity. hidden/none fall back to low.
_SEV = {"high": "high", "medium": "medium", "low": "low", "hidden": "low", "none": "info"}


class Entra:
    tool = "entra"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.cfg = creds.resolve("entra")
        self.configured = creds.configured("entra")
        self.base = (self.cfg.get("base_url") or "https://graph.microsoft.com").rstrip("/")
        self.login = (self.cfg.get("login_url") or "https://login.microsoftonline.com").rstrip("/")
        self._transport = transport

    def _token(self, tenant: str) -> str:
        if not tenant:
            raise ConnectorError("Entra: no tenant id for this client")
        with make_client(self.login, transport=self._transport) as http:
            r = http.post(
                f"/{tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.cfg.get("client_id", ""),
                    "client_secret": self.cfg.get("client_secret", ""),
                    "scope": f"{self.base}/.default",
                },
            )
        if r.status_code >= 400:
            detail = ""
            try:
                detail = r.json().get("error_description", "")[:120]
            except Exception:  # noqa: BLE001
                pass
            raise ConnectorError(f"Entra: token request failed (HTTP {r.status_code}) {detail}".strip())
        tok = r.json().get("access_token")
        if not tok:
            raise ConnectorError("Entra: token response had no access_token")
        return tok

    def _graph_get(self, token: str, path: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        url = path
        with make_client(self.base, headers={"Authorization": f"Bearer {token}"},
                         transport=self._transport) as http:
            for _ in range(20):  # follow @odata.nextLink, bounded
                r = http.get(url, params=params if url == path else None)
                if r.status_code == 401:
                    raise ConnectorError("Entra: Graph rejected the token (check app permissions and consent)")
                if r.status_code == 403:
                    raise ConnectorError("Entra: Graph denied access (IdentityRiskEvent.Read.All not consented?)")
                if r.status_code >= 400:
                    raise ConnectorError(f"Entra: Graph HTTP {r.status_code} on {url}")
                body = r.json()
                out.extend(body.get("value") or [])
                nxt = body.get("@odata.nextLink")
                if not nxt:
                    break
                url = nxt
        return out

    def devices(self, ref: str) -> list[dict]:
        # Identity signals are not device inventory; the managed-services device list
        # stays the EDR/RMM view. Return nothing here.
        return []

    def alerts(self, ref: str, since=None) -> list[dict]:
        token = self._token(ref)
        params = {"$top": "200", "$orderby": "detectedDateTime desc"}
        if since:
            stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            params["$filter"] = f"detectedDateTime ge {stamp}"
        rows = self._graph_get(token, "/v1.0/identityProtection/riskDetections", params)
        out = []
        for d in rows:
            rid = str(d.get("id") or "")
            if not rid:
                continue
            level = (d.get("riskLevel") or "low").lower()
            state = (d.get("riskState") or "").lower()
            sev = _SEV.get(level, "medium")
            if state in ("confirmedcompromised",):
                sev = "critical"
            upn = d.get("userPrincipalName") or d.get("userDisplayName") or "unknown user"
            where = d.get("location") or {}
            loc = ", ".join(x for x in [where.get("city"), where.get("countryOrRegion")] if x)
            out.append({
                "external_id": rid,
                "kind": "identity",
                "severity": sev,
                "title": f"{d.get('riskEventType') or 'identity risk'}: {upn}",
                "detail": " · ".join(x for x in [
                    f"risk {level}", f"state {state or 'unknown'}",
                    f"IP {d.get('ipAddress')}" if d.get("ipAddress") else "",
                    loc, d.get("detectionTimingType") or ""] if x),
                "tool_status": state,
                "occurred_at": parse_dt(d.get("detectedDateTime") or d.get("activityDateTime")),
                "link": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/"
                        "SecurityMenuBlade/~/RiskDetections",
                "resolved": state in ("remediated", "dismissed"),
                "raw": {k: d.get(k) for k in (
                    "riskEventType", "riskLevel", "riskState", "riskDetail", "source",
                    "userPrincipalName", "ipAddress", "activity")},
            })
        return out
