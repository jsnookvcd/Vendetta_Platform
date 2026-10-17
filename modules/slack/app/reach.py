"""Calls into the platform modules. Same contract SABINE uses: the module's own
token, X-Vendetta-Actor: slack, and here also X-Vendetta-On-Behalf-Of naming the
member of staff, so the IR timeline and SABINE's ledger record the person who
acted. `call` never raises."""
from __future__ import annotations

import json
import logging

import httpx

from .config import settings

log = logging.getLogger(__name__)
_TRANSPORT: httpx.BaseTransport | None = None


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
    if "platform" not in out and settings.platform_url:
        out["platform"] = {"base_url": settings.platform_url.rstrip("/"), "token": settings.platform_token,
                           "public_url": settings.platform_public_url.rstrip("/")}
    return out


def public_url(key: str) -> str:
    return directory().get(key, {}).get("public_url", "")


def call(key: str, method: str, path: str, *, person: str = "", params: dict | None = None,
         json_body: dict | None = None, timeout: float = 12.0) -> dict:
    """Return {ok, status, data, detail}."""
    entry = directory().get(key)
    if not entry:
        return {"ok": False, "status": 0, "data": None, "detail": f"{key} is not wired to the Slack responder"}
    headers = {"X-Vendetta-Actor": settings.actor_name}
    if entry.get("token"):
        headers["Authorization"] = f"Bearer {entry['token']}"
    if person:
        headers["X-Vendetta-On-Behalf-Of"] = person
    try:
        with httpx.Client(timeout=timeout, headers=headers, transport=_TRANSPORT) as http:
            r = http.request(method, f"{entry['base_url']}{path}", params=params, json=json_body)
    except httpx.HTTPError as e:
        return {"ok": False, "status": 0, "data": None, "detail": f"{key} unreachable ({type(e).__name__})"}
    data = None
    if r.headers.get("content-type", "").startswith("application/json"):
        try:
            data = r.json()
        except ValueError:
            data = None
    if r.status_code in (401, 403):
        detail = data.get("detail") if isinstance(data, dict) else ""
        return {"ok": False, "status": r.status_code, "data": data, "detail": detail or f"{key} refused the call"}
    if r.status_code >= 400:
        detail = data.get("detail") if isinstance(data, dict) else ""
        return {"ok": False, "status": r.status_code, "data": data,
                "detail": str(detail) if detail else f"{key} answered HTTP {r.status_code}"}
    return {"ok": True, "status": r.status_code, "data": data, "detail": ""}


def get(key: str, path: str, **kw) -> dict:
    return call(key, "GET", path, **kw)


def post(key: str, path: str, json_body: dict | None = None, **kw) -> dict:
    return call(key, "POST", path, json_body=json_body, **kw)


def get_bytes(key: str, path: str, *, person: str = "", params: dict | None = None,
              timeout: float = 60.0) -> tuple[bytes | None, str]:
    """A binary download (a PDF report). Returns (content, error)."""
    entry = directory().get(key)
    if not entry:
        return None, f"{key} is not wired to the Slack responder"
    headers = {"X-Vendetta-Actor": settings.actor_name}
    if entry.get("token"):
        headers["Authorization"] = f"Bearer {entry['token']}"
    if person:
        headers["X-Vendetta-On-Behalf-Of"] = person
    try:
        with httpx.Client(timeout=timeout, headers=headers, transport=_TRANSPORT) as http:
            r = http.get(f"{entry['base_url']}{path}", params=params)
    except httpx.HTTPError as e:
        return None, f"{key} unreachable ({type(e).__name__})"
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = ""
        return None, str(detail or f"{key} answered HTTP {r.status_code}")
    return r.content, ""
