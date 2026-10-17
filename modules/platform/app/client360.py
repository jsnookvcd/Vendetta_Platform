"""Client 360: one client's live picture, read from the modules that hold it.

Each module is read over HTTP with the per-module bearer token the control plane
already stores, in parallel, with a short timeout, and the result is cached
briefly per (module, client). A module that is down, slow, refusing the token or
not connected shows as unreachable with a reason and contributes nothing; it
never breaks the page. Only modules turned on for the client are read.

Every row read back is checked against the client's platform id before it is
counted, so a module that ignored the filter can never put another client's work
on this page.
"""
from __future__ import annotations

import datetime as dt
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from sqlalchemy.orm import Session

from . import journey
from .config import settings
from .db import Client, Module
from .registry import FINDING_MODULES

SEVERITIES = ("critical", "high", "medium", "low")
# Finding modules in display order; mdr serves its investigations as findings.
FINDING_ORDER = ("mdr", "managed-services", "dark-web-monitoring", "vulnerability-management", "penetration-testing")

# (module key, client id) -> (expires_at, result)
_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_transport: httpx.BaseTransport | None = None


def use_transport(t: httpx.BaseTransport | None) -> None:
    """Tests (or a deployment) may route every module read through one transport."""
    global _transport
    _transport = t
    clear_cache()


def clear_cache() -> None:
    _CACHE.clear()


def _sev(v) -> str:
    s = str(v or "").lower()
    return "low" if s in ("info", "informational", "") else (s if s in SEVERITIES else "low")


def _path_for(key: str, pid: str) -> str:
    if key in FINDING_MODULES:
        return f"/api/findings?status=active&platform_client_id={pid}"
    if key == "incident-response":
        return f"/api/ir-cases?status=active&platform_client_id={pid}"
    if key == "professional-services":
        return f"/api/engagements?status=open&platform_client_id={pid}"
    raise KeyError(key)


def _row_pid(key: str, row: dict) -> str:
    if key == "incident-response":
        return str(((row.get("client") or {}).get("platform_client_id")) or "")
    return str(((row.get("subject") or {}).get("platform_client_id")) or "")


def _fetch(m: Module, pid: str, transport: httpx.BaseTransport | None) -> dict:
    """{state: ok|unreachable|not_connected, detail, rows}. Never raises."""
    if not m.base_url:
        return {"state": "not_connected", "detail": "no base URL on Connections", "rows": []}
    headers = {"Authorization": f"Bearer {m.api_token}"} if m.api_token else {}
    try:
        with httpx.Client(timeout=settings.client360_timeout_seconds, headers=headers,
                          transport=transport or _transport) as http:
            r = http.get(f"{m.base_url.rstrip('/')}{_path_for(m.key, pid)}")
        if r.status_code in (401, 403):
            return {"state": "unreachable", "detail": "module rejected the token", "rows": []}
        if r.status_code != 200:
            return {"state": "unreachable", "detail": f"http {r.status_code}", "rows": []}
        data = r.json()
        rows = data if isinstance(data, list) else (data.get("items") or data.get("findings") or [])
        rows = [x for x in rows if isinstance(x, dict) and _row_pid(m.key, x) == pid]
        return {"state": "ok", "detail": "", "rows": rows}
    except Exception as e:  # noqa: BLE001
        return {"state": "unreachable", "detail": f"unreachable: {type(e).__name__}", "rows": []}


def _read(m: Module, pid: str, transport: httpx.BaseTransport | None, force: bool) -> dict:
    now = time.time()
    key = (m.key, pid)
    if not force:
        hit = _CACHE.get(key)
        if hit and hit[0] > now:
            return hit[1]
    res = _fetch(m, pid, transport)
    _CACHE[key] = (now + settings.client360_cache_seconds, res)
    return res


def _finding_block(m: Module, res: dict) -> dict:
    by = {s: 0 for s in SEVERITIES}
    items = []
    for f in res["rows"]:
        s = _sev(f.get("severity"))
        by[s] += 1
        items.append({"id": f.get("id"), "title": f.get("title") or f.get("type") or "finding", "severity": s,
                      "status": f.get("native_status") or f.get("status") or "",
                      "url": f.get("url") or f.get("link") or ""})
    rank = {s: n for n, s in enumerate(SEVERITIES)}
    items.sort(key=lambda x: rank[x["severity"]])
    return {"key": m.key, "display_name": m.display_name, "state": res["state"], "detail": res["detail"],
            "total": sum(by.values()), "by_severity": by, "top": items[:5]}


def _mdr_block(res: dict) -> dict:
    items = []
    for f in res["rows"]:
        items.append({"id": f.get("id"), "number": f.get("number") or f.get("case_ref") or "",
                      "title": f.get("title") or "investigation", "severity": _sev(f.get("severity")),
                      "status": f.get("native_status") or f.get("status") or "", "verdict": f.get("verdict") or "",
                      "opened_at": f.get("opened_at"), "acknowledged_at": f.get("acknowledged_at")})
    return {"state": res["state"], "detail": res["detail"], "open": len(items),
            "unacknowledged": sum(1 for i in items if not i["acknowledged_at"]), "items": items[:10]}


def _ir_block(res: dict) -> dict:
    cases = [{"id": c.get("id"), "number": c.get("number") or c.get("case_id") or "", "title": c.get("title") or "",
              "severity": _sev(c.get("severity")), "status": c.get("status") or "", "opened_at": c.get("opened_at"),
              "lead": c.get("lead") or ""} for c in res["rows"]]
    return {"state": res["state"], "detail": res["detail"], "open": len(cases), "cases": cases}


def _osp_block(res: dict) -> dict:
    engagements, waiting = [], 0
    for e in res["rows"]:
        delivered = [d for d in (e.get("deliverables") or []) if d.get("status") == "delivered"]
        waiting += len(delivered)
        engagements.append({"id": e.get("id"), "name": e.get("name") or "", "status": e.get("status") or "",
                            "overdue": bool(e.get("overdue")), "progress": e.get("progress"),
                            "waiting": [{"id": d.get("id"), "title": d.get("title") or "",
                                         "delivered_at": d.get("delivered_at")} for d in delivered]})
    return {"state": res["state"], "detail": res["detail"], "open": len(engagements),
            "deliverables_waiting": waiting, "engagements": engagements}


def _off() -> dict:
    return {"state": "not_enabled", "detail": "not turned on for this client", "rows": []}


def build(db: Session, client: Client, modules: list[Module], *, transport: httpx.BaseTransport | None = None,
          force: bool = False) -> dict:
    enabled = client.enabled_modules()
    by_key = {m.key: m for m in modules}
    wanted = [k for k in (*FINDING_ORDER, "incident-response", "professional-services")
              if k in by_key and k in enabled and by_key[k].status != "planned"]
    results: dict[str, dict] = {}
    if wanted:
        with ThreadPoolExecutor(max_workers=min(8, len(wanted))) as pool:
            futs = {k: pool.submit(_read, by_key[k], client.id, transport, force) for k in wanted}
            results = {k: f.result() for k, f in futs.items()}

    findings = []
    for k in FINDING_ORDER:
        if k not in by_key:
            continue
        res = results.get(k) or _off()
        findings.append(_finding_block(by_key[k], res))
    tot = {s: sum(f["by_severity"][s] for f in findings) for s in SEVERITIES}

    items = journey.items_for(db, client.id)
    counts = {s: sum(1 for i in items if i.status == s) for s in journey.STATUSES}
    drafts = [c for c in journey.comms_for(db, client.id) if c.status == "draft"]
    return {
        "client": {"id": client.id, "name": client.name, "tier": client.tier or "core",
                   "account_lead": client.account_lead or "", "commitments": client.commitments(),
                   "services": sorted(enabled)},
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "findings": {"total": sum(tot.values()), "by_severity": tot, "modules": findings},
        "mdr": _mdr_block(results.get("mdr") or _off()),
        "incident_response": _ir_block(results.get("incident-response") or _off()),
        "professional_services": _osp_block(results.get("professional-services") or _off()),
        "journey": {"counts": counts, "items": [journey.item_dict(i) for i in items]},
        "communications": {"drafts": len(drafts), "items": [journey.comm_dict(c) for c in drafts]},
    }
