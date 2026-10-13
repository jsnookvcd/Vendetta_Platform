"""Acronis Cyber Protect Cloud connector.

A partner-tenant API client on the account's data center. Token: POST
/api/2/idp/token with Basic(client_id, client_secret) and client_credentials,
cached and renewed before the 2-hour expiry. A managed client maps to a customer
tenant UUID.

Alerts come from Alert Manager v1 (cursor paging, nanosecond time filters);
per-workload backup state from resource_management v4 resource_statuses; and
"run backup now" from PUT policy_management/v4/applications/run, with the policy
id looked up per resource. Deleting an alert dismisses it, and the unfiltered
DELETE would dismiss everything, so only the by-id form is used here."""
from __future__ import annotations

import logging
import time

import httpx

from ..config import settings
from .base import ConnectorError, make_client, parse_dt, recent

log = logging.getLogger(__name__)

_SEV = {"ok": "info", "information": "info", "warning": "medium", "error": "high", "critical": "critical"}
BACKUP_FRESH_HOURS = 36


class Acronis:
    tool = "acronis"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.configured = bool(settings.acronis_dc_url and settings.acronis_client_id
                               and settings.acronis_client_secret)
        self.base = settings.acronis_dc_url.rstrip("/")
        self._http = make_client(self.base, transport=transport)
        self._token: tuple[str, float] | None = None

    def _bearer(self) -> dict:
        if not self._token or self._token[1] < time.time() + 900:
            r = self._http.post("/api/2/idp/token",
                                auth=(settings.acronis_client_id, settings.acronis_client_secret),
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                                data={"grant_type": "client_credentials"})
            if r.status_code >= 400:
                raise ConnectorError(f"Acronis: token request failed, HTTP {r.status_code}")
            body = r.json()
            expires = float(body.get("expires_on") or (time.time() + float(body.get("expires_in") or 7200)))
            self._token = (body["access_token"], expires)
        return {"Authorization": f"Bearer {self._token[0]}"}

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = self._http.get(path, params=params, headers=self._bearer())
        if r.status_code == 401:
            self._token = None
            raise ConnectorError("Acronis: token rejected")
        if r.status_code >= 400:
            raise ConnectorError(f"Acronis: HTTP {r.status_code} on {path}")
        return r.json()

    def _items(self, path: str, params: dict) -> list[dict]:
        out: list[dict] = []
        after = None
        for _ in range(50):
            q = dict(params)
            if after:
                q = {"after": after, "limit": params.get("limit", 200)}
            body = self._get(path, q)
            items = body.get("items") or []
            out.extend(items)
            after = ((body.get("paging") or {}).get("cursors") or {}).get("after")
            if not after or not items:
                break
        return out

    # ---------------------------------------------------------------- reads
    def tenants(self) -> list[dict]:
        me = self._get(f"/api/2/clients/{settings.acronis_client_id}")
        rows = self._get(f"/api/2/tenants/{me['tenant_id']}/children", {"include_details": "true"})
        return [{"id": t.get("id"), "name": t.get("name"), "kind": t.get("kind"), "enabled": t.get("enabled")}
                for t in rows.get("items") or [] if isinstance(t, dict)]

    def devices(self, tenant_id: str) -> list[dict]:
        rows = self._items("/api/resource_management/v4/resource_statuses",
                           {"tenant_id": tenant_id, "limit": 200})
        out = []
        for rs in rows:
            ctx = rs.get("context") or {}
            if ctx.get("deleted_at"):
                continue
            policies = rs.get("policies") or []
            ok_times = [t for t in (parse_dt(p.get("last_success_run_time") or p.get("last_success_run"))
                                    for p in policies) if t]
            last_ok = max(ok_times) if ok_times else None
            agg = ((rs.get("aggregate") or {}).get("status")) or ""
            if agg == "no_policies_applied" or not policies:
                status = "unknown"
            elif last_ok and recent(last_ok, BACKUP_FRESH_HOURS * 60):
                status = "online"
            else:
                status = "offline"  # backups stale
            nxt = max((p.get("next_run_time") or "" for p in policies), default="")
            out.append({
                "external_id": str(ctx.get("id")),
                "hostname": ctx.get("user_defined_name") or ctx.get("name") or "",
                "platform": ctx.get("type") or "",
                "status": status,
                "agent_version": "",
                "last_seen": last_ok,
                "link": self.base,
                "raw": {"aggregate_status": agg, "next_run_time": nxt,
                        "policies": [{"type": p.get("type"),
                                      "last_run": p.get("last_run_time") or p.get("last_run")}
                                     for p in policies[:5]]},
            })
        return out

    def alerts(self, tenant_id: str, since=None) -> list[dict]:
        params: dict = {"tenant": tenant_id, "order": "desc(created_at)", "limit": 200}
        if since:
            params["updated_at"] = f"gt({int(since.timestamp())}000000000)"  # nanoseconds
        rows = self._items("/api/alert_manager/v1/alerts", params)
        out = []
        for a in rows:
            details = a.get("details") or {}
            out.append({
                "external_id": str(a.get("id")),
                "kind": "backup",
                "severity": _SEV.get((a.get("severity") or "").lower(), "medium"),
                "title": details.get("title") or a.get("type") or "Acronis alert",
                "detail": " · ".join(x for x in [details.get("description"), details.get("resourceName"),
                                                 details.get("planName")] if x)[:2000],
                "tool_status": "dismissed" if a.get("deletedAt") else "active",
                "occurred_at": parse_dt(a.get("createdAt") or a.get("receivedAt")),
                "link": self.base,
                "resolved": bool(a.get("deletedAt")),
                "raw": {"type": a.get("type"), "category": a.get("category"),
                        "resourceId": details.get("resourceId"), "planId": details.get("planId")},
            })
        return out

    # ---------------------------------------------------------------- actions
    def dismiss_alert(self, alert_id: str) -> None:
        if not alert_id:
            raise ConnectorError("Acronis: refusing to dismiss without an alert id")
        r = self._http.delete(f"/api/alert_manager/v1/alerts/{alert_id}", headers=self._bearer())
        if r.status_code not in (200, 204):
            raise ConnectorError(f"Acronis: HTTP {r.status_code} dismissing alert")

    def run_backup_for_resource(self, resource_id: str) -> str:
        """Find the resource's backup policy and run it for that resource only."""
        apps = self._get("/api/policy_management/v4/applications",
                         {"context_id": resource_id}).get("items") or []
        policy_id = ""
        for app in apps:
            pol = app.get("policy") or {}
            if (pol.get("type") or "").startswith("policy.backup"):
                parents = pol.get("parent_ids") or []
                policy_id = parents[0] if parents else pol.get("id", "")
                break
        if not policy_id:
            raise ConnectorError("Acronis: no backup plan applied to this workload")
        r = self._http.put("/api/policy_management/v4/applications/run", headers=self._bearer(),
                           json={"state": "running", "policy_id": policy_id, "context_ids": [resource_id]})
        if r.status_code == 422:
            raise ConnectorError("Acronis: the plan is disabled or the workload has no quota")
        if r.status_code not in (200, 202, 204):
            raise ConnectorError(f"Acronis: HTTP {r.status_code} starting backup")
        return policy_id
