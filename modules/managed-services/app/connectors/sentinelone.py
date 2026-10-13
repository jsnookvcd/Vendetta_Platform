"""SentinelOne Management API v2.1 connector.

Auth: Authorization: ApiToken <token> against https://<tenant>.sentinelone.net.
One MSP-scoped token covers every site; each call is narrowed with siteIds, which
is how a client's slice of the tenancy is addressed. Cursor pagination; nextCursor
can be None or the literal string "null" on the last page. Action bodies are
{"filter": {"ids": [...]}, "data": {...}} and an empty filter would hit everything
in scope, so every action here refuses an empty id list."""
from __future__ import annotations

import logging

import httpx

from ..config import settings
from .base import ConnectorError, make_client, parse_dt

log = logging.getLogger(__name__)

MITIGATE_ACTIONS = ["kill", "quarantine", "remediate", "rollback-remediation", "un-quarantine"]
INCIDENT_STATUSES = ["unresolved", "in_progress", "resolved"]
VERDICTS = ["undefined", "true_positive", "false_positive", "suspicious"]

_SEV = {"malicious": "critical", "suspicious": "medium", "n/a": "low"}


class SentinelOne:
    tool = "sentinelone"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        from .. import creds

        self.cfg = creds.resolve("sentinelone")
        self.configured = creds.configured("sentinelone")
        self.base = (self.cfg["url"] or "").rstrip("/")
        self._http = make_client(
            f"{self.base}/web/api/v2.1",
            headers={"Authorization": f"ApiToken {self.cfg['api_token']}"},
            transport=transport,
        )

    def _get(self, path: str, params: dict) -> list[dict]:
        out: list[dict] = []
        cursor = None
        for _ in range(50):
            q = {k: v for k, v in params.items() if v not in (None, "")}
            q["limit"] = 1000
            if cursor:
                q = {"cursor": cursor, "limit": 1000}  # other params with cursor return 400
            r = self._http.get(path, params=q)
            if r.status_code == 401:
                raise ConnectorError("SentinelOne: invalid API token")
            if r.status_code >= 400:
                raise ConnectorError(f"SentinelOne: HTTP {r.status_code} on {path}")
            body = r.json()
            data = body.get("data") or []
            out.extend(data if isinstance(data, list) else [data])
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor or cursor == "null":
                break
        return out

    def _post(self, path: str, body: dict) -> int:
        r = self._http.post(path, json=body)
        if r.status_code >= 400:
            raise ConnectorError(f"SentinelOne: HTTP {r.status_code} on {path}: {r.text[:200]}")
        return int((r.json().get("data") or {}).get("affected") or 0)

    @staticmethod
    def _ids_filter(ids: list[str]) -> dict:
        ids = [i for i in ids if i]
        if not ids:
            # An empty filter would apply to the whole tenancy. Never send one.
            raise ConnectorError("SentinelOne: refusing an action with no target ids")
        return {"ids": ids}

    # ---------------------------------------------------------------- reads
    def sites(self) -> list[dict]:
        rows: list[dict] = []
        body = self._http.get("/sites", params={"limit": 1000, "state": "active"}).json()
        for s in ((body.get("data") or {}).get("sites") or []):
            rows.append({"id": str(s.get("id")), "name": s.get("name"), "account": s.get("accountName")})
        return rows

    def devices(self, site_ids: str) -> list[dict]:
        rows = self._get("/agents", {"siteIds": site_ids})
        out = []
        for a in rows:
            if a.get("isDecommissioned"):
                continue
            net = a.get("networkStatus") or ""
            if net == "disconnected":
                status = "isolated"
            elif net in ("disconnecting", "connecting"):
                status = "isolating"
            elif a.get("isActive"):
                status = "online"
            else:
                status = "offline"
            out.append({
                "external_id": str(a.get("id")),
                "hostname": a.get("computerName") or "",
                "platform": a.get("osName") or a.get("osType") or "",
                "status": status,
                "agent_version": a.get("agentVersion") or "",
                "last_seen": parse_dt(a.get("lastActiveDate")),
                "link": f"{self.base}/sentinels/devices" if self.base else "",
                "raw": {"uuid": a.get("uuid"), "infected": a.get("infected"),
                        "activeThreats": a.get("activeThreats"), "siteId": a.get("siteId"),
                        "lastLoggedInUserName": a.get("lastLoggedInUserName")},
            })
        return out

    def alerts(self, site_ids: str, since=None) -> list[dict]:
        params: dict = {"siteIds": site_ids, "sortBy": "createdAt", "sortOrder": "asc"}
        if since:
            params["updatedAt__gte"] = since.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        rows = self._get("/threats", params)
        out = []
        for t in rows:
            info = t.get("threatInfo") or {}
            agent = t.get("agentRealtimeInfo") or {}
            tid = str(t.get("id") or info.get("threatId"))
            confidence = (info.get("confidenceLevel") or "n/a").lower()
            sev = _SEV.get(confidence, "medium")
            if confidence == "malicious" and info.get("mitigationStatus") == "mitigated":
                sev = "high"  # contained malicious: still worth review, no longer critical
            out.append({
                "external_id": tid,
                "kind": "threat",
                "severity": sev,
                "title": info.get("threatName") or "SentinelOne threat",
                "detail": " · ".join(x for x in [
                    info.get("classification"), f"mitigation {info.get('mitigationStatus') or 'unknown'}",
                    agent.get("agentComputerName")] if x),
                "tool_status": info.get("incidentStatus") or "",
                "occurred_at": parse_dt(info.get("createdAt")),
                "link": f"{self.base}/incidents/threats/{tid}/overview" if self.base else "",
                "resolved": info.get("incidentStatus") == "resolved",
                "device_external_id": str(agent.get("agentId") or ""),
                "raw": {"threatInfo": {k: info.get(k) for k in (
                    "threatName", "classification", "confidenceLevel", "mitigationStatus",
                    "incidentStatus", "analystVerdict", "filePath", "sha1")},
                    "agent": {"name": agent.get("agentComputerName"), "id": agent.get("agentId")}},
            })
        return out

    # ---------------------------------------------------------------- actions
    def mitigate(self, threat_ids: list[str], action: str) -> int:
        if action not in MITIGATE_ACTIONS:
            raise ConnectorError(f"SentinelOne: unknown mitigation {action!r}")
        return self._post(f"/threats/mitigate/{action}", {"filter": self._ids_filter(threat_ids)})

    def set_incident(self, threat_ids: list[str], status: str, verdict: str = "") -> int:
        if status not in INCIDENT_STATUSES:
            raise ConnectorError(f"SentinelOne: unknown incident status {status!r}")
        data: dict = {"incidentStatus": status}
        if verdict:
            if verdict not in VERDICTS:
                raise ConnectorError(f"SentinelOne: unknown verdict {verdict!r}")
            data["analystVerdict"] = verdict
        return self._post("/threats/incident", {"filter": self._ids_filter(threat_ids), "data": data})

    def disconnect(self, agent_ids: list[str]) -> int:
        return self._post("/agents/actions/disconnect", {"filter": self._ids_filter(agent_ids)})

    def reconnect(self, agent_ids: list[str]) -> int:
        return self._post("/agents/actions/connect", {"filter": self._ids_filter(agent_ids)})
