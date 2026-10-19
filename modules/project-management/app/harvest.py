"""Harvest API v2: time entries, projects and tasks.

Every request carries the Harvest-Account-Id header and the admin token. Entries are
written with user_id set to the PM's Harvest user (matched by email), so the hours
land on the right person even though one token is used. An analyst may create,
change and delete only their own entries; an admin may act for anyone.
"""
from __future__ import annotations

import datetime as dt
import logging
import time

import httpx

from . import integrations

log = logging.getLogger(__name__)

# Tests swap in an httpx.MockTransport here.
TRANSPORT: httpx.BaseTransport | None = None
_USERS: dict = {"at": 0.0, "by_email": {}}
_USER_TTL = 600


class HarvestError(Exception):
    pass


def configured() -> bool:
    cfg = integrations.resolve()
    return bool(cfg["harvest_account_id"] and cfg["harvest_token"])


def _request(method: str, path: str, *, params: dict | None = None, json: dict | None = None) -> dict:
    cfg = integrations.resolve()
    if not (cfg["harvest_account_id"] and cfg["harvest_token"]):
        raise HarvestError("Harvest is not connected. An admin sets the account ID and token on Integrations.")
    headers = {"Harvest-Account-Id": cfg["harvest_account_id"], "Authorization": f"Bearer {cfg['harvest_token']}",
               "User-Agent": "Vendetta Project Management (legal@vendettacd.io)", "Accept": "application/json"}
    url = path if path.startswith("http") else f"{cfg['harvest_url'].rstrip('/')}/{path.lstrip('/')}"
    try:
        with httpx.Client(timeout=20.0, transport=TRANSPORT, headers=headers) as http:
            r = http.request(method, url, params=params, json=json)
    except httpx.HTTPError as e:
        raise HarvestError(f"Harvest unreachable: {type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise HarvestError("Harvest rejected the token or this account lacks permission")
    if r.status_code == 404:
        raise HarvestError("Harvest has no such record")
    if r.status_code == 422:
        try:
            msg = r.json().get("message") or "validation failed"
        except ValueError:
            msg = "validation failed"
        raise HarvestError(f"Harvest refused the entry: {msg}")
    if r.status_code >= 400:
        raise HarvestError(f"Harvest HTTP {r.status_code}")
    if r.status_code == 204 or not r.content:
        return {}
    try:
        return r.json()
    except ValueError as e:
        raise HarvestError("Harvest returned something that is not JSON") from e


def _paged(path: str, key: str, params: dict | None = None, limit: int = 5000) -> list[dict]:
    out: list[dict] = []
    params = {**(params or {}), "per_page": 2000}
    body = _request("GET", path, params=params)
    while True:
        out.extend(body.get(key) or [])
        nxt = (body.get("links") or {}).get("next")
        if not nxt or len(out) >= limit:
            return out[:limit]
        body = _request("GET", nxt)


# ---------------------------------------------------------------- people
def user_id_for(email: str) -> str:
    """The Harvest user id for a staff email, from a ten-minute cache of /users."""
    email = (email or "").strip().lower()
    if time.time() - _USERS["at"] > _USER_TTL or email not in _USERS["by_email"]:
        users = _paged("users", "users", {"is_active": "true"})
        _USERS.update(at=time.time(), by_email={(u.get("email") or "").lower(): str(u["id"]) for u in users})
    uid = _USERS["by_email"].get(email)
    if not uid:
        raise HarvestError(f"No active Harvest user has the email {email}")
    return uid


# ---------------------------------------------------------------- projects and tasks
def list_projects(query: str = "", active_only: bool = True) -> list[dict]:
    params = {"is_active": "true"} if active_only else {}
    rows = _paged("projects", "projects", params)
    q = query.strip().lower()
    out = []
    for p in rows:
        client = (p.get("client") or {}).get("name") or ""
        if q and q not in (p.get("name") or "").lower() and q not in client.lower() \
                and q not in (p.get("code") or "").lower():
            continue
        out.append({"id": str(p["id"]), "name": p.get("name"), "code": p.get("code") or "", "client": client,
                    "budget_hours": p.get("budget") if p.get("budget_by") in ("project", "task", "person") else None,
                    "is_billable": p.get("is_billable")})
    return out


def get_project(project_id: str) -> dict:
    p = _request("GET", f"projects/{project_id}")
    return {"id": str(p["id"]), "name": p.get("name"), "code": p.get("code") or "",
            "client": (p.get("client") or {}).get("name") or ""}


def list_tasks(project_id: str) -> list[dict]:
    rows = _paged(f"projects/{project_id}/task_assignments", "task_assignments", {"is_active": "true"})
    return [{"id": str((t.get("task") or {}).get("id")), "name": (t.get("task") or {}).get("name"),
             "billable": t.get("billable")} for t in rows]


def resolve_task(project_id: str, task: str) -> str:
    """A task id from an id or a (case-insensitive, unique-prefix) task name."""
    task = (task or "").strip()
    tasks = list_tasks(project_id)
    if not tasks:
        raise HarvestError("That Harvest project has no active tasks assigned")
    for t in tasks:
        if t["id"] == task:
            return t["id"]
    exact = [t for t in tasks if (t["name"] or "").lower() == task.lower()]
    if len(exact) == 1:
        return exact[0]["id"]
    prefix = [t for t in tasks if (t["name"] or "").lower().startswith(task.lower())] if task else []
    if len(prefix) == 1:
        return prefix[0]["id"]
    names = ", ".join(t["name"] for t in tasks)
    if not task:
        raise HarvestError(f"Name a Harvest task. This project has: {names}")
    raise HarvestError(f"'{task}' does not match one Harvest task on this project. Choose one of: {names}")


# ---------------------------------------------------------------- time entries
def _entry(e: dict) -> dict:
    return {"id": str(e["id"]), "spent_date": e.get("spent_date"), "hours": e.get("hours"),
            "notes": e.get("notes") or "", "user": (e.get("user") or {}).get("name"),
            "user_id": str((e.get("user") or {}).get("id") or ""),
            "project_id": str((e.get("project") or {}).get("id") or ""),
            "project": (e.get("project") or {}).get("name"),
            "task_id": str((e.get("task") or {}).get("id") or ""), "task": (e.get("task") or {}).get("name"),
            "client": (e.get("client") or {}).get("name"), "billable": e.get("billable"),
            "is_locked": e.get("is_locked"), "is_running": e.get("is_running")}


def create_entry(*, user_email: str, project_id: str, task_id: str, spent_date: dt.date,
                 hours: float, notes: str = "") -> dict:
    if hours <= 0 or hours > 24:
        raise HarvestError("Hours must be more than 0 and at most 24")
    body = {"user_id": int(user_id_for(user_email)), "project_id": int(project_id), "task_id": int(task_id),
            "spent_date": spent_date.isoformat(), "hours": round(float(hours), 2), "notes": notes}
    return _entry(_request("POST", "time_entries", json=body))


def get_entry(entry_id: str) -> dict:
    return _entry(_request("GET", f"time_entries/{entry_id}"))


def update_entry(entry_id: str, **changes) -> dict:
    body = {}
    if changes.get("hours") is not None:
        h = float(changes["hours"])
        if h <= 0 or h > 24:
            raise HarvestError("Hours must be more than 0 and at most 24")
        body["hours"] = round(h, 2)
    if changes.get("notes") is not None:
        body["notes"] = changes["notes"]
    if changes.get("spent_date") is not None:
        body["spent_date"] = changes["spent_date"].isoformat()
    if changes.get("project_id"):
        body["project_id"] = int(changes["project_id"])
    if changes.get("task_id"):
        body["task_id"] = int(changes["task_id"])
    if not body:
        raise HarvestError("Nothing to change")
    return _entry(_request("PATCH", f"time_entries/{entry_id}", json=body))


def delete_entry(entry_id: str) -> None:
    _request("DELETE", f"time_entries/{entry_id}")


def list_entries(*, user_email: str | None = None, project_id: str | None = None,
                 start: dt.date | None = None, end: dt.date | None = None, limit: int = 500) -> list[dict]:
    params: dict = {}
    if user_email:
        params["user_id"] = user_id_for(user_email)
    if project_id:
        params["project_id"] = project_id
    if start:
        params["from"] = start.isoformat()
    if end:
        params["to"] = end.isoformat()
    return [_entry(e) for e in _paged("time_entries", "time_entries", params, limit=limit)]


def project_hours(project_id: str, start: dt.date | None = None, end: dt.date | None = None) -> dict:
    """Hours logged on a project, total and by person and task, for burn."""
    entries = list_entries(project_id=project_id, start=start, end=end, limit=20000)
    total = round(sum(float(e["hours"] or 0) for e in entries), 2)
    by_person: dict[str, float] = {}
    by_task: dict[str, float] = {}
    for e in entries:
        by_person[e["user"] or "?"] = round(by_person.get(e["user"] or "?", 0) + float(e["hours"] or 0), 2)
        by_task[e["task"] or "?"] = round(by_task.get(e["task"] or "?", 0) + float(e["hours"] or 0), 2)
    return {"total_hours": total, "entries": len(entries), "by_person": by_person, "by_task": by_task}
