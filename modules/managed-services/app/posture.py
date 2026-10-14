"""Pre-incident posture: the conditions that have not fired an alert yet but are
how the next incident starts. The SOC queue shows what is attacking now; this shows
what is undefended, unwatched, or left in a bad state, so the team can close the gap
before it becomes a 2am call.

Everything here is computed from data the module already holds (clients, their tool
mapping, device state, and open alerts), so it needs no new integration. Each finding
is one risk item with a category, a severity (risk or watch), the client it belongs
to, and a plain-language headline and detail.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .config import TOOL_NAMES, settings
from .db import Alert, Client, Device

# Categories, worst first, with the label the UI shows.
CATEGORIES = {
    "coverage-gap": "Coverage gaps",
    "endpoints-dark": "Endpoints not reporting",
    "backup-risk": "Backup at risk",
    "stale-telemetry": "Telemetry stale",
    "isolation-review": "Isolation needs review",
}
_SEVERITY_RANK = {"risk": 0, "watch": 1}
_CATEGORY_RANK = {k: i for i, k in enumerate(CATEGORIES)}

# Tools that put an agent on endpoints. Coverage and telemetry gaps are judged
# against these; the RMM (SuperOps) and backup (Acronis) are handled on their own
# terms, so a PSA with no "devices" is never miscounted as unprotected endpoints.
ENDPOINT_TOOLS = ("sentinelone", "crowdstrike", "huntress")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _age_days(ts: dt.datetime | None, now: dt.datetime) -> float | None:
    return None if ts is None else (now - ts).total_seconds() / 86400.0


def _item(category, severity, client, headline, detail):
    return {"category": category, "severity": severity, "client": client.name,
            "client_id": client.id, "headline": headline, "detail": detail}


def scan(db: Session, now: dt.datetime | None = None) -> list[dict]:
    """Return every open posture risk across the managed book, worst first."""
    now = now or _utcnow()
    stale_days = settings.posture_stale_endpoint_days
    stale_sync = dt.timedelta(hours=settings.posture_stale_sync_hours)
    iso_hours = settings.posture_isolation_review_hours

    clients = db.execute(
        select(Client).where(Client.active.is_(True)).order_by(Client.name)
    ).scalars().all()
    devices = db.execute(select(Device)).scalars().all()
    open_alerts = db.execute(
        select(Alert).where(Alert.status != "resolved")).scalars().all()

    by_client_dev: dict[str, list[Device]] = {}
    for d in devices:
        by_client_dev.setdefault(d.client_id, []).append(d)
    backup_alerts: dict[str, int] = {}
    for a in open_alerts:
        if a.kind == "backup":
            backup_alerts[a.client_id] = backup_alerts.get(a.client_id, 0) + 1

    items: list[dict] = []
    for c in clients:
        devs = by_client_dev.get(c.id, [])
        mapped = c.tools  # tools with a tenancy mapping set
        by_tool: dict[str, list[Device]] = {}
        for d in devs:
            by_tool.setdefault(d.tool, []).append(d)

        # Coverage gaps: an endpoint tool is mapped for this client but no device
        # reports from it.
        missing = [t for t in mapped if t in ENDPOINT_TOOLS and not by_tool.get(t)]
        if missing:
            names = ", ".join(TOOL_NAMES.get(t, t) for t in missing)
            items.append(_item("coverage-gap", "risk", c,
                               f"{len(missing)} mapped tool{'s' if len(missing) != 1 else ''} with no agents reporting",
                               f"{names} mapped but returning no devices. The agent is not deployed, or not checking in."))

        # Endpoints dark: offline/unknown, or not seen within the stale window.
        dark = []
        for d in devs:
            age = _age_days(d.last_seen, now)
            if d.status in ("offline", "unknown") or (age is not None and age >= stale_days):
                dark.append((d, age))
        if dark:
            worst = max((a for _, a in dark if a is not None), default=None)
            sev = "risk" if any(a is not None and a >= stale_days for _, a in dark) else "watch"
            detail = f"{len(dark)} of {len(devs)} endpoint{'s' if len(devs) != 1 else ''} offline or not reporting"
            if worst is not None:
                detail += f"; oldest {int(worst)}d without check-in"
            items.append(_item("endpoints-dark", sev, c,
                               f"{len(dark)} endpoint{'s' if len(dark) != 1 else ''} dark", detail + "."))

        # Backup risk: a failed backup alert is open, or backup is mapped with no workloads.
        if backup_alerts.get(c.id):
            n = backup_alerts[c.id]
            items.append(_item("backup-risk", "risk", c,
                               f"{n} backup failure{'s' if n != 1 else ''} open",
                               "A backup job is failing. Restores are at risk until it succeeds again."))
        elif "acronis" in mapped and not by_tool.get("acronis"):
            items.append(_item("backup-risk", "watch", c, "Backup configured but no protected workloads",
                               "Acronis is mapped but no workloads are reporting. Nothing is being backed up."))

        # Stale telemetry: an endpoint tool's newest device sync is older than the window.
        stale_tools = []
        for t in mapped:
            if t not in ENDPOINT_TOOLS:
                continue
            tdevs = by_tool.get(t) or []
            if not tdevs:
                continue  # already a coverage gap
            newest = max((d.synced_at for d in tdevs if d.synced_at), default=None)
            if newest is None or (now - newest) > stale_sync:
                stale_tools.append((t, newest))
        if stale_tools:
            names = ", ".join(TOOL_NAMES.get(t, t) for t, _ in stale_tools)
            items.append(_item("stale-telemetry", "watch", c,
                               f"Telemetry stale from {len(stale_tools)} tool{'s' if len(stale_tools) != 1 else ''}",
                               f"No fresh data from {names} in over {settings.posture_stale_sync_hours}h. You may be blind to new activity."))

        # Isolation review: a host left isolated longer than the review window.
        for d in devs:
            if d.status in ("isolated", "isolating"):
                ref = d.synced_at or d.last_seen
                hrs = None if ref is None else (now - ref).total_seconds() / 3600.0
                if hrs is not None and hrs >= iso_hours:
                    items.append(_item("isolation-review", "watch", c,
                                       f"{d.hostname} isolated {int(hrs)}h",
                                       "Host has been isolated past the review window. Confirm it is intentional and plan recovery."))

    items.sort(key=lambda it: (_CATEGORY_RANK[it["category"]], _SEVERITY_RANK[it["severity"]], it["client"]))
    return items


def summarize(items: list[dict]) -> dict:
    """Counts for the dashboard tile and panel header."""
    risk = sum(1 for it in items if it["severity"] == "risk")
    watch = sum(1 for it in items if it["severity"] == "watch")
    by_cat = {k: 0 for k in CATEGORIES}
    for it in items:
        by_cat[it["category"]] += 1
    return {"total": len(items), "risk": risk, "watch": watch, "by_category": by_cat}


def grouped(items: list[dict]) -> list[dict]:
    """Items arranged by category for the posture page, worst categories first."""
    out = []
    for cat, label in CATEGORIES.items():
        rows = [it for it in items if it["category"] == cat]
        if rows:
            out.append({"category": cat, "label": label, "items": rows,
                        "risk": sum(1 for it in rows if it["severity"] == "risk")})
    return out
