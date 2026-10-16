"""The module directory and roster push.

Two directions of the control plane's link to the modules live here:

- apply_env_directory: the deployment (Terraform) renders MODULE_DIRECTORY, a JSON
  map of each module's service address, bearer token and public URL. It is applied
  to every module row that has no base URL yet, so a fresh host is wired on first
  boot; an operator can re-apply it from the Connections page to overwrite edits.
- push_sync: after a client changes here, every connected module is told to pull
  the roster now (POST /api/provision/sync), so an activation lands in the module
  within seconds rather than at its next scheduled pull. Pushes run in a background
  thread and never block the request; the last outcome per module is kept for the
  Connections page and the readiness screen.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import Module

log = logging.getLogger(__name__)

# module key -> {"at", "ok", "detail"}
LAST_PUSH: dict[str, dict] = {}


def env_directory() -> dict[str, dict]:
    raw = (settings.module_directory or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        log.warning("MODULE_DIRECTORY is not valid JSON; ignoring")
        return {}
    out = {}
    for key, entry in (data.items() if isinstance(data, dict) else []):
        if isinstance(entry, dict):
            out[key] = {"base_url": (entry.get("base_url") or "").rstrip("/"),
                        "token": entry.get("token") or "",
                        "public_url": (entry.get("public_url") or "").rstrip("/")}
    return out


def apply_env_directory(db: Session, force: bool = False) -> int:
    """Copy the deployment directory onto module rows. Without force only rows with
    no base URL are touched, so operator edits survive restarts."""
    applied = 0
    for key, entry in env_directory().items():
        m = db.get(Module, key)
        if not m:
            continue
        if not force and m.base_url:
            continue
        changed = False
        if entry["base_url"] and entry["base_url"] != m.base_url:
            m.base_url, changed = entry["base_url"], True
        if entry["token"] and entry["token"] != m.api_token:
            m.api_token, changed = entry["token"], True
        if entry["public_url"] and entry["public_url"] != m.public_url:
            m.public_url, changed = entry["public_url"], True
        if changed:
            applied += 1
    if applied:
        db.commit()
        log.info("module directory applied to %d module(s)", applied)
    return applied


def _push_one(key: str, base_url: str, token: str, transport: httpx.BaseTransport | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with httpx.Client(timeout=20.0, headers=headers, transport=transport) as http:
            r = http.post(f"{base_url.rstrip('/')}/api/provision/sync")
        if r.status_code == 200:
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            detail = ", ".join(f"{k} {v}" for k, v in body.items() if k in ("roster", "added", "updated", "deactivated"))
            res = {"ok": True, "detail": detail or "ok"}
        elif r.status_code == 404:
            res = {"ok": False, "detail": "module predates provisioning push; it will pull on its schedule"}
        elif r.status_code in (401, 403):
            res = {"ok": False, "detail": "module rejected the token"}
        else:
            res = {"ok": False, "detail": f"http {r.status_code}"}
    except (httpx.HTTPError, ValueError) as e:  # noqa: BLE001
        res = {"ok": False, "detail": f"unreachable: {type(e).__name__}"}
    res["at"] = dt.datetime.now(dt.timezone.utc)
    LAST_PUSH[key] = res
    return res


def targets(db: Session, keys: set[str] | None = None) -> list[tuple[str, str, str]]:
    rows = db.execute(select(Module).where(Module.status != "planned")).scalars().all()
    return [(m.key, m.base_url, m.api_token) for m in rows
            if m.base_url and (keys is None or m.key in keys)]


def push_sync(db: Session, keys: set[str] | None = None, wait: bool = False,
              transport: httpx.BaseTransport | None = None) -> dict[str, dict]:
    """Tell each connected module (or just `keys`) to pull the roster now. Returns
    the results when wait is True, else {} after starting the pushes in the
    background."""
    plan = targets(db, keys)
    if not plan:
        return {}
    if wait:
        return {k: _push_one(k, u, t, transport) for k, u, t in plan}

    def _run():
        for k, u, t in plan:
            r = _push_one(k, u, t, transport)
            log.info("roster push -> %s: %s", k, r["detail"])

    threading.Thread(target=_run, name="roster-push", daemon=True).start()
    return {}
