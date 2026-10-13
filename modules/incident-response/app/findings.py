"""Findings pull: the hub reads the shared finding model from each enabled module
and presents them per client. Modules feed the hub; the hub never reaches into a
module's database. Every pull degrades gracefully, so one module being down or slow
shows as unreachable and never breaks the page.

A finding is mapped to a hub client by the shared platform_client_id first, then by
client name, the same resolution escalation uses. Results are cached briefly.
"""
from __future__ import annotations

import logging
import time

import httpx

from .config import settings

log = logging.getLogger(__name__)

# name -> (expires_at, result)
_CACHE: dict[str, tuple[float, dict]] = {}


def _pull_one(source: dict, transport: httpx.BaseTransport | None = None) -> dict:
    """Return {name, reachable, findings, detail}. Never raises."""
    name = source["name"]
    base = source["base_url"].rstrip("/")
    headers = {"Authorization": f"Bearer {source['token']}"} if source.get("token") else {}
    try:
        with httpx.Client(timeout=6.0, transport=transport, headers=headers) as http:
            r = http.get(f"{base}/api/findings", params={"status": "active"})
        if r.status_code == 401 or r.status_code == 403:
            return {"name": name, "reachable": False, "findings": [], "detail": "auth rejected"}
        if r.status_code != 200:
            return {"name": name, "reachable": False, "findings": [], "detail": f"http {r.status_code}"}
        data = r.json()
        return {"name": name, "reachable": True, "findings": data if isinstance(data, list) else [], "detail": ""}
    except (httpx.HTTPError, ValueError) as e:  # noqa: BLE001
        return {"name": name, "reachable": False, "findings": [], "detail": f"unreachable: {type(e).__name__}"}


def discover_sources(transport: httpx.BaseTransport | None = None) -> list[dict]:
    """When FINDINGS_SOURCES is not set, ask the control plane for the finding-serving
    modules (base URL and token), so sources are configured once on the platform's
    Connections page. Returns [] if the platform is not configured or unreachable."""
    if not settings.platform_url:
        return []
    headers = {"Authorization": f"Bearer {settings.platform_token}"} if settings.platform_token else {}
    url = f"{settings.platform_url.rstrip('/')}/api/platform/modules"
    try:
        with httpx.Client(timeout=6.0, transport=transport, headers=headers) as http:
            r = http.get(url)
        if r.status_code != 200:
            log.warning("findings: platform module directory HTTP %s", r.status_code)
            return []
        return [{"name": m["name"], "base_url": m["base_url"].rstrip("/"), "token": m.get("token", "")}
                for m in (r.json().get("modules") or []) if m.get("base_url")]
    except (httpx.HTTPError, ValueError) as e:  # noqa: BLE001
        log.warning("findings: platform module directory unreachable: %s", type(e).__name__)
        return []


def pull_all(sources: list[dict] | None = None, transport: httpx.BaseTransport | None = None,
             force: bool = False) -> dict:
    """Pull findings from every source, cached per source. Returns
    {sources: [...], findings: [...]} where each finding carries its source name.
    Sources come from FINDINGS_SOURCES, else from the control-plane module directory."""
    if sources is None:
        sources = settings.finding_source_list() or discover_sources(transport)
    now = time.time()
    source_status, findings = [], []
    for s in sources:
        cached = _CACHE.get(s["name"]) if not force else None
        res = cached[1] if cached and cached[0] > now else _pull_one(s, transport)
        _CACHE[s["name"]] = (now + settings.findings_cache_seconds, res)
        source_status.append({"name": res["name"], "reachable": res["reachable"], "detail": res["detail"],
                              "count": len(res["findings"])})
        for f in res["findings"]:
            f = dict(f)
            f["_source"] = res["name"]
            findings.append(f)
    return {"sources": source_status, "findings": findings}


def _subject(f: dict) -> dict:
    return f.get("subject") or {}


def for_client(client, sources: list[dict] | None = None, transport: httpx.BaseTransport | None = None,
               force: bool = False) -> dict:
    """Findings that belong to one hub client, matched by platform_client_id then by
    name. Returns {sources, findings}."""
    pulled = pull_all(sources, transport, force)
    pid = (client.platform_client_id or "").strip()
    name = (client.name or "").strip().lower()
    mine = []
    for f in pulled["findings"]:
        subj = _subject(f)
        fpid = (subj.get("platform_client_id") or "").strip()
        fname = (subj.get("client") or "").strip().lower()
        if (pid and fpid and pid == fpid) or (fname and fname == name):
            mine.append(f)
    return {"sources": pulled["sources"], "findings": mine}


def clear_cache() -> None:
    _CACHE.clear()
