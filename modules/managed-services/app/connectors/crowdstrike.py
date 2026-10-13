"""CrowdStrike Falcon connector (MSSP / Flight Control).

One parent API client; a client's slice is its child CID, and every call first
takes an OAuth2 token locked to that child with member_cid. Tokens last 30
minutes and are cached per CID. Hosts come from the combined devices endpoint,
alerts from the current alerts v2 API (not the deprecated detects), status
updates go through PATCH alerts v3, and network containment through
devices-actions. The alert's own falcon_host_link is used as the deep link."""
from __future__ import annotations

import logging
import time

import httpx

from ..config import settings
from .base import ConnectorError, make_client, parse_dt, recent

log = logging.getLogger(__name__)

ALERT_STATUSES = ["new", "in_progress", "closed", "reopened"]
_SEV = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


class CrowdStrike:
    tool = "crowdstrike"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.configured = bool(settings.crowdstrike_client_id and settings.crowdstrike_client_secret)
        self._http = make_client(settings.crowdstrike_base_url.rstrip("/"), transport=transport)
        self._tokens: dict[str, tuple[str, float]] = {}

    def _token(self, member_cid: str) -> str:
        cached = self._tokens.get(member_cid)
        if cached and cached[1] > time.time() + 60:
            return cached[0]
        form = {"client_id": settings.crowdstrike_client_id,
                "client_secret": settings.crowdstrike_client_secret}
        if member_cid:
            form["member_cid"] = member_cid.lower().split("-")[0]
        r = self._http.post("/oauth2/token", data=form,
                            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        if r.status_code not in (200, 201):
            raise ConnectorError(f"CrowdStrike: token request failed, HTTP {r.status_code}")
        body = r.json()
        token = body["access_token"]
        self._tokens[member_cid] = (token, time.time() + int(body.get("expires_in", 1800)))
        return token

    def _api(self, member_cid: str, method: str, path: str, *, params: dict | None = None,
             json: dict | None = None) -> dict:
        r = self._http.request(method, path, params=params, json=json,
                               headers={"Authorization": f"Bearer {self._token(member_cid)}"})
        if r.status_code == 401:
            self._tokens.pop(member_cid, None)
            raise ConnectorError("CrowdStrike: token rejected")
        if r.status_code >= 400:
            errs = []
            try:
                errs = [e.get("message") for e in r.json().get("errors") or []]
            except Exception:  # noqa: BLE001
                pass
            raise ConnectorError(f"CrowdStrike: HTTP {r.status_code} on {path}: {errs[:1] or r.text[:150]}")
        return r.json()

    # ---------------------------------------------------------------- reads
    def children(self) -> list[dict]:
        ids = self._api("", "GET", "/mssp/queries/children/v1", params={"limit": 100}).get("resources") or []
        if not ids:
            return []
        rows = self._api("", "POST", "/mssp/entities/children/GET/v2", json={"ids": ids}).get("resources") or []
        return [{"cid": c.get("child_cid"), "name": c.get("name")} for c in rows]

    def devices(self, member_cid: str) -> list[dict]:
        out: list[dict] = []
        offset = None
        for _ in range(20):
            params: dict = {"limit": 500, "sort": "hostname.asc",
                            "fields": "device_id,hostname,platform_name,os_version,agent_version,last_seen,status"}
            if offset:
                params["offset"] = offset
            body = self._api(member_cid, "GET", "/devices/combined/devices/v1", params=params)
            for d in body.get("resources") or []:
                last_seen = parse_dt(d.get("last_seen"))
                cs_status = d.get("status") or ""
                if cs_status == "contained":
                    status = "isolated"
                elif cs_status in ("containment_pending", "lift_containment_pending"):
                    status = "isolating"
                else:
                    status = "online" if recent(last_seen, 65) else "offline"
                out.append({
                    "external_id": str(d.get("device_id")),
                    "hostname": d.get("hostname") or "",
                    "platform": " ".join(x for x in [d.get("platform_name"), d.get("os_version")] if x),
                    "status": status,
                    "agent_version": d.get("agent_version") or "",
                    "last_seen": last_seen,
                    "link": f"{settings.crowdstrike_console_url}/hosts/detail/{d.get('device_id')}",
                    "raw": {"cs_status": cs_status},
                })
            offset = (body.get("meta", {}).get("pagination") or {}).get("next") or (body.get("meta", {}).get("pagination") or {}).get("offset")
            if not offset or not body.get("resources"):
                break
        return out

    def alerts(self, member_cid: str, since=None) -> list[dict]:
        out: list[dict] = []
        after = None
        fql = "product:'epp'"
        if since:
            fql += f"+updated_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
        for _ in range(20):
            body = self._api(member_cid, "POST", "/alerts/combined/alerts/v1",
                             json={"filter": fql, "sort": "created_timestamp|asc", "limit": 1000,
                                   **({"after": after} if after else {})})
            rows = body.get("resources") or []
            for a in rows:
                device = a.get("device") or {}
                out.append({
                    "external_id": a.get("composite_id") or a.get("id"),
                    "kind": "detection",
                    "severity": _SEV.get((a.get("severity_name") or "").lower(), "medium"),
                    "title": a.get("display_name") or a.get("name") or "Falcon detection",
                    "detail": " · ".join(x for x in [
                        a.get("description"), a.get("tactic"), a.get("technique"), device.get("hostname")] if x),
                    "tool_status": a.get("status") or "",
                    "occurred_at": parse_dt(a.get("created_timestamp")),
                    "link": a.get("falcon_host_link") or "",
                    "resolved": a.get("status") == "closed",
                    "device_external_id": str(device.get("device_id") or ""),
                    "raw": {"severity": a.get("severity"), "tactic": a.get("tactic"),
                            "technique": a.get("technique"), "status": a.get("status")},
                })
            after = (body.get("meta", {}).get("pagination") or {}).get("after")
            if not after or not rows:
                break
        return out

    # ---------------------------------------------------------------- actions
    def update_alert(self, member_cid: str, composite_ids: list[str], status: str, comment: str = "") -> int:
        if status not in ALERT_STATUSES:
            raise ConnectorError(f"CrowdStrike: unknown alert status {status!r}")
        if not composite_ids:
            raise ConnectorError("CrowdStrike: refusing an action with no target ids")
        actions = [{"name": "update_status", "value": status}]
        if comment:
            actions.append({"name": "append_comment", "value": comment[:500]})
        body = self._api(member_cid, "PATCH", "/alerts/entities/alerts/v3",
                         params={"include_hidden": "true"},
                         json={"composite_ids": composite_ids, "action_parameters": actions})
        return int((body.get("meta", {}).get("writes") or {}).get("resources_affected") or 0)

    def contain(self, member_cid: str, device_ids: list[str]) -> None:
        self._device_action(member_cid, device_ids, "contain")

    def lift_containment(self, member_cid: str, device_ids: list[str]) -> None:
        self._device_action(member_cid, device_ids, "lift_containment")

    def _device_action(self, member_cid: str, device_ids: list[str], action: str) -> None:
        if not device_ids:
            raise ConnectorError("CrowdStrike: refusing an action with no target ids")
        self._api(member_cid, "POST", "/devices/entities/devices-actions/v2",
                  params={"action_name": action}, json={"ids": device_ids})
