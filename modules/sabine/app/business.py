"""Business sources: Harvest (budgets, capacity) and HubSpot (renewals, new wins).

Each is optional. Without credentials the source is skipped, perception records
nothing for it, and readiness reports it as not configured. Calls go through
httpx with a module-level transport that tests replace with a MockTransport.

Harvest API v2: every request carries Harvest-Account-Id and a Bearer token.
- GET /reports/project_budget?is_active=true: budget, budget_spent per project.
- GET /users?is_active=true: weekly_capacity in seconds.
- GET /reports/time/team?from=YYYYMMDD&to=YYYYMMDD: total_hours per user.

HubSpot CRM v3/v4 with a private-app Bearer token:
- POST /crm/v3/objects/deals/search: renewals (dealtype=renewal or the renewal
  pipeline) closing inside the window, and deals closed won in the lookback.
- POST /crm/v4/associations/deals/companies/batch/read and
  POST /crm/v3/objects/companies/batch/read: the associated company's name.
"""
from __future__ import annotations

import datetime as dt
import logging

import httpx

from .config import settings

log = logging.getLogger(__name__)

_TRANSPORT: httpx.BaseTransport | None = None  # tests inject a MockTransport
MAX_PAGES = 10


def set_transport(t: httpx.BaseTransport | None) -> None:
    global _TRANSPORT
    _TRANSPORT = t


class SourceError(Exception):
    pass


def _num(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


class Harvest:
    def __init__(self, account_id: str, token: str, base_url: str):
        self.account_id, self.token, self.base_url = account_id.strip(), token.strip(), base_url.rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self.account_id and self.token)

    def _pages(self, path: str, key: str, params: dict | None = None) -> list[dict]:
        headers = {"Harvest-Account-Id": self.account_id, "Authorization": f"Bearer {self.token}",
                   "User-Agent": "SABINE (Vendetta Platform)"}
        out: list[dict] = []
        page = 1
        try:
            with httpx.Client(timeout=30.0, headers=headers, transport=_TRANSPORT) as http:
                while page and page <= MAX_PAGES:
                    r = http.get(f"{self.base_url}{path}", params={**(params or {}), "page": page})
                    if r.status_code in (401, 403):
                        raise SourceError("Harvest rejected the token")
                    if r.status_code >= 400:
                        raise SourceError(f"Harvest http {r.status_code}")
                    data = r.json()
                    out += list(data.get(key) or [])
                    page = data.get("next_page")
        except httpx.HTTPError as e:
            raise SourceError(f"Harvest unreachable: {type(e).__name__}") from e
        except ValueError as e:
            raise SourceError("Harvest returned something that is not JSON") from e
        return out

    def projects(self) -> list[dict]:
        out = []
        for r in self._pages("/reports/project_budget", "results", {"is_active": "true"}):
            budget, spent = _num(r.get("budget")), _num(r.get("budget_spent"))
            out.append({"id": str(r.get("project_id")), "name": r.get("project_name") or "", "client": r.get("client_name") or "",
                        "budget_by": r.get("budget_by") or "", "budget": budget, "spent": spent,
                        "remaining": _num(r.get("budget_remaining")),
                        "pct": round(100 * spent / budget, 1) if budget > 0 else None})
        return out

    def capacity(self, today: dt.date | None = None) -> list[dict]:
        today = today or dt.date.today()
        monday = today - dt.timedelta(days=today.weekday())
        users = self._pages("/users", "users", {"is_active": "true"})
        hours = {str(r.get("user_id")): _num(r.get("total_hours"))
                 for r in self._pages("/reports/time/team", "results",
                                      {"from": monday.strftime("%Y%m%d"), "to": today.strftime("%Y%m%d")})}
        out = []
        for u in users:
            cap = _num(u.get("weekly_capacity")) / 3600.0
            h = hours.get(str(u.get("id")), 0.0)
            out.append({"id": str(u.get("id")), "name": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip(),
                        "email": u.get("email") or "", "capacity_hours": round(cap, 1), "hours": round(h, 1),
                        "pct": round(100 * h / cap, 1) if cap > 0 else None,
                        "week": f"{monday.isocalendar()[0]}-W{monday.isocalendar()[1]:02d}"})
        return out


class HubSpot:
    PROPS = ["dealname", "dealstage", "closedate", "amount", "pipeline", "dealtype", "hs_is_closed_won"]

    def __init__(self, token: str, base_url: str, renewal_pipeline: str = ""):
        self.token, self.base_url, self.renewal_pipeline = token.strip(), base_url.rstrip("/"), renewal_pipeline.strip()

    @property
    def configured(self) -> bool:
        return bool(self.token)

    def _post(self, http: httpx.Client, path: str, body: dict) -> dict:
        r = http.post(f"{self.base_url}{path}", json=body)
        if r.status_code in (401, 403):
            raise SourceError("HubSpot rejected the token")
        if r.status_code >= 400:
            raise SourceError(f"HubSpot http {r.status_code}")
        return r.json()

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=30.0, headers={"Authorization": f"Bearer {self.token}"}, transport=_TRANSPORT)

    def _search(self, http: httpx.Client, groups: list[dict]) -> list[dict]:
        out, after = [], None
        for _ in range(MAX_PAGES):
            body = {"filterGroups": groups, "properties": self.PROPS, "limit": 100,
                    "sorts": [{"propertyName": "closedate", "direction": "ASCENDING"}]}
            if after:
                body["after"] = after
            data = self._post(http, "/crm/v3/objects/deals/search", body)
            out += list(data.get("results") or [])
            after = ((data.get("paging") or {}).get("next") or {}).get("after")
            if not after:
                break
        return out

    def _companies(self, http: httpx.Client, deal_ids: list[str]) -> dict[str, str]:
        if not deal_ids:
            return {}
        assoc = self._post(http, "/crm/v4/associations/deals/companies/batch/read",
                           {"inputs": [{"id": d} for d in deal_ids]})
        first: dict[str, str] = {}
        for r in assoc.get("results") or []:
            to = r.get("to") or []
            if to:
                first[str((r.get("from") or {}).get("id"))] = str(to[0].get("toObjectId"))
        if not first:
            return {}
        comp = self._post(http, "/crm/v3/objects/companies/batch/read",
                          {"properties": ["name"], "inputs": [{"id": c} for c in set(first.values())]})
        names = {str(c.get("id")): (c.get("properties") or {}).get("name") or "" for c in comp.get("results") or []}
        return {d: names.get(c, "") for d, c in first.items()}

    def _shape(self, rows: list[dict], companies: dict[str, str]) -> list[dict]:
        out = []
        for d in rows:
            p = d.get("properties") or {}
            out.append({"id": str(d.get("id")), "name": p.get("dealname") or "", "stage": p.get("dealstage") or "",
                        "close_date": (p.get("closedate") or "")[:10], "amount": _num(p.get("amount")),
                        "pipeline": p.get("pipeline") or "", "dealtype": p.get("dealtype") or "",
                        "company": companies.get(str(d.get("id")), "")})
        return out

    def deals(self, renewal_days: int, won_days: int, today: dt.date | None = None) -> dict:
        today = today or dt.date.today()
        start = dt.datetime.combine(today, dt.time.min, tzinfo=dt.timezone.utc)
        ms = lambda t: str(int(t.timestamp() * 1000))  # noqa: E731
        window = [{"propertyName": "closedate", "operator": "BETWEEN", "value": ms(start),
                   "highValue": ms(start + dt.timedelta(days=renewal_days + 1))},
                  {"propertyName": "hs_is_closed", "operator": "NEQ", "value": "true"}]
        groups = [{"filters": [{"propertyName": "dealtype", "operator": "EQ", "value": "renewal"}, *window]}]
        if self.renewal_pipeline:
            groups.append({"filters": [{"propertyName": "pipeline", "operator": "EQ", "value": self.renewal_pipeline}, *window]})
        won_groups = [{"filters": [{"propertyName": "hs_is_closed_won", "operator": "EQ", "value": "true"},
                                   {"propertyName": "closedate", "operator": "GTE", "value": ms(start - dt.timedelta(days=won_days))}]}]
        try:
            with self._client() as http:
                renewals = self._search(http, groups)
                won = self._search(http, won_groups)
                companies = self._companies(http, sorted({str(d.get("id")) for d in renewals + won}))
        except httpx.HTTPError as e:
            raise SourceError(f"HubSpot unreachable: {type(e).__name__}") from e
        except ValueError as e:
            raise SourceError("HubSpot returned something that is not JSON") from e
        return {"renewals": self._shape(renewals, companies), "won": self._shape(won, companies)}


def harvest() -> Harvest:
    return Harvest(settings.harvest_account_id, settings.harvest_token, settings.harvest_url)


def hubspot() -> HubSpot:
    return HubSpot(settings.hubspot_token, settings.hubspot_url, settings.hubspot_renewal_pipeline)


def status() -> dict:
    return {"harvest": "configured" if harvest().configured else "not configured",
            "hubspot": "configured" if hubspot().configured else "not configured"}
