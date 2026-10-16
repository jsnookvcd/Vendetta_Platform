"""How MARLOW reaches the platform and the modules.

The deployment renders MODULE_DIRECTORY: every module MARLOW may talk to, with its
service URL on the shared docker network, the token that module accepts, and its
public URL for links people follow. MARLOW presents the module's token and names
itself in X-Vendetta-Actor, so every module's audit log attributes the call to
"api:marlow" rather than to an anonymous API caller.

All calls go through `call`, which never raises: a module that is down returns a
failed result and the rest of the cycle continues.
"""
from __future__ import annotations

import json
import logging

import httpx

from .config import settings

log = logging.getLogger(__name__)

_TRANSPORT: httpx.BaseTransport | None = None  # tests inject a MockTransport here


def set_transport(t: httpx.BaseTransport | None) -> None:
    global _TRANSPORT
    _TRANSPORT = t


def directory() -> dict[str, dict]:
    raw = (settings.module_directory or "").strip()
    out: dict[str, dict] = {}
    if raw:
        try:
            data = json.loads(raw)
        except ValueError:
            log.warning("MODULE_DIRECTORY is not valid JSON")
            data = {}
        for key, entry in (data.items() if isinstance(data, dict) else []):
            if isinstance(entry, dict) and entry.get("base_url"):
                out[key] = {"base_url": entry["base_url"].rstrip("/"), "token": entry.get("token", ""),
                            "public_url": (entry.get("public_url") or "").rstrip("/")}
    # The control plane is always reachable through its own settings too.
    if "platform" not in out and settings.platform_url:
        out["platform"] = {"base_url": settings.platform_url.rstrip("/"), "token": settings.platform_token,
                           "public_url": settings.platform_public_url.rstrip("/")}
    return out


def public_url(key: str) -> str:
    return directory().get(key, {}).get("public_url", "")


def call(key: str, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None,
         timeout: float = 15.0) -> dict:
    """Return {ok, status, data, detail}. Never raises."""
    entry = directory().get(key)
    if not entry:
        return {"ok": False, "status": 0, "data": None, "detail": f"{key} is not in MODULE_DIRECTORY"}
    headers = {"X-Vendetta-Actor": settings.actor_name}
    if entry.get("token"):
        headers["Authorization"] = f"Bearer {entry['token']}"
    try:
        with httpx.Client(timeout=timeout, headers=headers, transport=_TRANSPORT) as http:
            r = http.request(method, f"{entry['base_url']}{path}", params=params, json=json_body)
    except httpx.HTTPError as e:
        return {"ok": False, "status": 0, "data": None, "detail": f"{key} unreachable: {type(e).__name__}"}
    data = None
    if r.headers.get("content-type", "").startswith("application/json"):
        try:
            data = r.json()
        except ValueError:
            data = None
    if r.status_code in (401, 403):
        return {"ok": False, "status": r.status_code, "data": data, "detail": f"{key} rejected the token"}
    if r.status_code >= 400:
        detail = (data or {}).get("detail") or (data or {}).get("reason") if isinstance(data, dict) else ""
        return {"ok": False, "status": r.status_code, "data": data, "detail": f"{key} http {r.status_code}{': ' + str(detail) if detail else ''}"}
    return {"ok": True, "status": r.status_code, "data": data, "detail": ""}


def get(key: str, path: str, **kw) -> dict:
    return call(key, "GET", path, **kw)


def post(key: str, path: str, json_body: dict | None = None, **kw) -> dict:
    return call(key, "POST", path, json_body=json_body, **kw)
