"""Cross-module overview: probe each reachable module for health and open-item
counts, cached briefly so page loads do not hammer the modules. Every probe
degrades gracefully; a module that is down or slow shows as unreachable, never an
error, so one dead module never breaks the main screen."""
from __future__ import annotations

import time

import httpx

from .config import settings
from .registry import PROBE

# key -> (expires_at, result)
_CACHE: dict[str, tuple[float, dict]] = {}


def _severity_counts(items: list, sev_key: str) -> tuple[int, int]:
    """(total, critical+high). Case tools use status to judge open-ness; the item
    lists we call already return open items, so total is len(items)."""
    crit = 0
    for it in items:
        sev = str(it.get(sev_key, "")).lower()
        if sev in ("critical", "high"):
            crit += 1
    return len(items), crit


def probe_module(module, transport: httpx.BaseTransport | None = None, force: bool = False) -> dict:
    """Return {reachable, enabled, open, critical, label, detail, tools}."""
    now = time.time()
    if not force:
        cached = _CACHE.get(module.key)
        if cached and cached[0] > now:
            return cached[1]

    spec = PROBE.get(module.key)
    result = {"reachable": False, "enabled": None, "open": None, "critical": 0,
              "label": spec["label"] if spec else "", "detail": "", "tools": {}, "readiness": {}}
    if not module.base_url or not spec:
        result["detail"] = "no endpoint" if spec else "no live feed"
        _CACHE[module.key] = (now + settings.probe_cache_seconds, result)
        return result

    headers = {"Authorization": f"Bearer {module.api_token}"} if module.api_token else {}
    base = module.base_url.rstrip("/")
    try:
        with httpx.Client(timeout=6.0, transport=transport, headers=headers) as http:
            man = http.get(f"{base}{spec['manifest']}")
            if man.status_code == 200:
                body = man.json()
                result["reachable"] = True
                result["enabled"] = body.get("enabled")
                result["tools"] = body.get("tools") or {}
                result["readiness"] = body.get("readiness") or {}
                if result["enabled"] is False:
                    result["detail"] = "module disabled"
                else:
                    items = http.get(f"{base}{spec['items']}")
                    if items.status_code == 200:
                        data = items.json()
                        rows = data if isinstance(data, list) else data.get("items", [])
                        result["open"], result["critical"] = _severity_counts(rows, spec["severity_key"])
                    else:
                        result["detail"] = f"items HTTP {items.status_code}"
            elif man.status_code in (401, 403):
                result["detail"] = "auth rejected"
            else:
                result["detail"] = f"HTTP {man.status_code}"
    except Exception as e:  # noqa: BLE001
        result["detail"] = f"unreachable: {type(e).__name__}"

    _CACHE[module.key] = (now + settings.probe_cache_seconds, result)
    return result


def overview(modules, transport: httpx.BaseTransport | None = None) -> dict[str, dict]:
    return {m.key: probe_module(m, transport=transport) for m in modules}


def clear_cache() -> None:
    _CACHE.clear()
