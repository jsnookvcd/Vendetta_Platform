"""Huntress MDR connector (public API v1).

HTTP Basic auth with a user-based API key and secret (the account-level key is
read-only and cannot approve remediations). 60 requests/minute. Pagination follows
next_page_url until it is absent, which works with both the page-number and
page-token revisions of the API. A client maps to a Huntress organization.

Incident reports carry SOC-written summaries; remediation approval and rejection
are bulk-only per report, and resolving a report requires every remediation to be
approved first (the API returns 409 otherwise)."""
from __future__ import annotations

import logging

import httpx

from ..config import settings
from .base import ConnectorError, make_client, parse_dt, recent

log = logging.getLogger(__name__)

_SEV = {"low": "low", "high": "high", "critical": "critical"}
RESOLVED_STATUSES = {"closed", "dismissed", "partner_dismissed", "resolved"}


class Huntress:
    tool = "huntress"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        from .. import creds

        self.cfg = creds.resolve("huntress")
        self.configured = creds.configured("huntress")
        self._http = make_client("https://api.huntress.io/v1",
                                 auth=(self.cfg["api_key"], self.cfg["api_secret"]),
                                 transport=transport)

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = self._http.get(path, params={k: v for k, v in (params or {}).items() if v not in (None, "")})
        if r.status_code == 401:
            raise ConnectorError("Huntress: invalid API credentials")
        if r.status_code == 429:
            raise ConnectorError("Huntress: rate limited (60/min)")
        if r.status_code >= 400:
            raise ConnectorError(f"Huntress: HTTP {r.status_code} on {path}")
        return r.json()

    def _list(self, path: str, items_key: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        body = self._get(path, {**(params or {}), "limit": 500})
        for _ in range(100):
            out.extend(body.get(items_key) or [])
            nxt = (body.get("pagination") or {}).get("next_page_url")
            if not nxt:
                break
            r = self._http.get(nxt)
            if r.status_code >= 400:
                break
            body = r.json()
        return out

    def _post(self, path: str, json: dict | None = None) -> dict:
        r = self._http.post(path, json=json)
        if r.status_code == 409:
            raise ConnectorError("Huntress: not allowed in the report's current state "
                                 "(unapproved remediations, or already handled)")
        if r.status_code == 422:
            raise ConnectorError("Huntress: the report is not in a resolvable state")
        if r.status_code >= 400:
            raise ConnectorError(f"Huntress: HTTP {r.status_code} on {path}")
        return r.json() if r.content else {}

    # ---------------------------------------------------------------- reads
    def organizations(self) -> list[dict]:
        rows = self._list("/organizations", "organizations")
        return [{"id": str(o.get("id")), "name": o.get("name"), "agents": o.get("agents_count")} for o in rows]

    def devices(self, org_id: str) -> list[dict]:
        rows = self._list("/agents", "agents", {"organization_id": org_id})
        out = []
        for a in rows:
            fw = a.get("firewall_status") or ""
            last = parse_dt(a.get("last_callback_at"))
            if fw == "Isolated":
                status = "isolated"
            elif fw in ("Pending Isolation", "Pending Release"):
                status = "isolating"
            else:
                status = "online" if recent(last, 45) else "offline"
            out.append({
                "external_id": str(a.get("id")),
                "hostname": a.get("hostname") or "",
                "platform": " ".join(x for x in [a.get("platform"), a.get("os")] if x),
                "status": status,
                "agent_version": a.get("version") or "",
                "last_seen": last,
                "link": self.cfg["base_url"],
                "raw": {"edr_version": a.get("edr_version"), "defender_status": a.get("defender_status"),
                        "firewall_status": fw},
            })
        return out

    def alerts(self, org_id: str, since=None) -> list[dict]:
        rows = self._list("/incident_reports", "incident_reports", {"organization_id": org_id})
        out = []
        for ir in rows:
            status = (ir.get("status") or "").lower()
            rem = ir.get("remediations") or {}
            rem_items = rem.get("items") if isinstance(rem, dict) else rem
            out.append({
                "external_id": str(ir.get("id")),
                "kind": "incident",
                "severity": _SEV.get((ir.get("severity") or "").lower(), "high"),
                "title": ir.get("subject") or "Huntress incident report",
                "detail": (ir.get("summary") or "")[:2000],
                "tool_status": ir.get("status") or "",
                "occurred_at": parse_dt(ir.get("sent_at")) or parse_dt(ir.get("updated_at")),
                "link": self.cfg["base_url"],
                "resolved": status in RESOLVED_STATUSES,
                "device_external_id": str(ir.get("agent_id") or ""),
                "raw": {"indicator_types": ir.get("indicator_types"),
                        "remediations": [{"action": x.get("action"), "type": x.get("type"),
                                          "status": x.get("status")} for x in (rem_items or [])[:10]]},
            })
        return out

    def remediations(self, report_id: str) -> list[dict]:
        return self._list(f"/incident_reports/{report_id}/remediations", "remediations")

    # ---------------------------------------------------------------- actions
    def approve_remediations(self, report_id: str) -> None:
        self._post(f"/incident_reports/{report_id}/remediations/bulk_approval")

    def reject_remediations(self, report_id: str, comment: str) -> None:
        self._post(f"/incident_reports/{report_id}/remediations/bulk_rejection",
                   {"comment": comment or "Rejected from Vendetta Managed Services", "useful": True})

    def resolve_report(self, report_id: str) -> None:
        self._post(f"/incident_reports/{report_id}/resolution")

    def isolate(self, agent_id: str, reason: str) -> None:
        self._post(f"/agents/{agent_id}/isolation",
                   {"reason": reason or "Isolated by Vendetta SOC", "strict_isolation": False})

    def release(self, agent_id: str) -> None:
        r = self._http.delete(f"/agents/{agent_id}/isolation")
        if r.status_code >= 400:
            raise ConnectorError(f"Huntress: HTTP {r.status_code} releasing isolation")
