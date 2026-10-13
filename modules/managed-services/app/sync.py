"""Sync engine: pulls each client's slice of each deployed tool into the
normalized Device and Alert tables.

Upserts key on (tool, external_id). A new alert arrives open; when the vendor
resolves it on their side, the module's status follows unless a tech resolved it
here first. Sync never un-resolves or un-publishes anything, so triage work and
portal publications survive every run. Per-tool sync outcomes are kept in memory
(LAST_SYNC) for the settings and client pages, and failures are recorded, not
raised, so one dead tool never stops the others."""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy.orm import Session

from . import connectors
from .config import SEVERITY_ORDER, TOOLS
from .connectors import ConnectorError
from .db import Alert, Client, Device, utcnow

log = logging.getLogger(__name__)

# {(client_id, tool): {"at": dt, "ok": bool, "detail": str, "devices": n, "alerts": n}}
LAST_SYNC: dict[tuple[str, str], dict] = {}


def _upsert_device(db: Session, client: Client, tool: str, d: dict) -> Device:
    row = db.query(Device).filter_by(tool=tool, external_id=d["external_id"]).one_or_none()
    if row is None:
        row = Device(tool=tool, external_id=d["external_id"])
        db.add(row)
    row.client_id = client.id
    row.hostname = d.get("hostname") or row.hostname
    row.platform = d.get("platform") or row.platform
    row.status = d.get("status") or "unknown"
    row.agent_version = d.get("agent_version") or ""
    row.last_seen = d.get("last_seen")
    row.link = d.get("link") or ""
    row.raw = d.get("raw") or {}
    row.synced_at = utcnow()
    return row


def _upsert_alert(db: Session, client: Client, tool: str, a: dict,
                  devices_by_ext: dict[str, Device]) -> tuple[Alert, bool]:
    row = db.query(Alert).filter_by(tool=tool, external_id=a["external_id"]).one_or_none()
    created = row is None
    if row is None:
        row = Alert(tool=tool, external_id=a["external_id"], status="open")
        db.add(row)
    row.client_id = client.id
    row.kind = a.get("kind") or "alert"
    row.severity = a.get("severity") if a.get("severity") in SEVERITY_ORDER else "medium"
    row.title = (a.get("title") or "")[:4000]
    row.detail = (a.get("detail") or "")[:8000]
    row.tool_status = (a.get("tool_status") or "")[:60]
    row.occurred_at = a.get("occurred_at") or row.occurred_at
    row.link = a.get("link") or row.link
    row.raw = a.get("raw") or {}
    dev = devices_by_ext.get(str(a.get("device_external_id") or ""))
    if dev:
        row.device_id = dev.id
    if a.get("resolved") and row.status != "resolved":
        row.status = "resolved"
    row.updated_at = utcnow()
    row.synced_at = utcnow()
    return row, created


def sync_client_tool(db: Session, client: Client, tool: str) -> dict:
    """Sync one client's slice of one tool. Returns a result dict and never raises."""
    ref = client.tool_ref(tool)
    conn = connectors.get(tool)
    result = {"at": utcnow(), "ok": True, "detail": "", "devices": 0, "alerts": 0, "new_alerts": 0}
    if not ref:
        result.update(ok=False, detail="not mapped for this client")
    elif not getattr(conn, "configured", False):
        result.update(ok=False, detail="tool not configured (missing credentials)")
    else:
        try:
            devices = conn.devices(ref)
            by_ext: dict[str, Device] = {}
            for d in devices:
                by_ext[d["external_id"]] = _upsert_device(db, client, tool, d)
            db.flush()
            alerts = conn.alerts(ref)
            new = 0
            for a in alerts:
                _, created = _upsert_alert(db, client, tool, a, by_ext)
                new += int(created)
            db.commit()
            result.update(devices=len(devices), alerts=len(alerts), new_alerts=new)
        except ConnectorError as e:
            db.rollback()
            result.update(ok=False, detail=str(e))
        except Exception as e:  # noqa: BLE001
            db.rollback()
            log.exception("sync %s/%s failed", client.name, tool)
            result.update(ok=False, detail=f"unexpected: {e}")
    LAST_SYNC[(client.id, tool)] = result
    return result


def sync_client(db: Session, client: Client) -> dict[str, dict]:
    return {tool: sync_client_tool(db, client, tool) for tool in client.tools}


def sync_all(db: Session) -> dict:
    counts = {"clients": 0, "ok": 0, "failed": 0, "new_alerts": 0}
    for client in db.query(Client).filter_by(active=True).all():
        if not client.tools:
            continue
        counts["clients"] += 1
        for tool, res in sync_client(db, client).items():
            counts["ok" if res["ok"] else "failed"] += 1
            counts["new_alerts"] += res.get("new_alerts", 0)
    return counts


def last_sync(client_id: str, tool: str) -> dict | None:
    return LAST_SYNC.get((client_id, tool))


def stale(client_id: str, tool: str, minutes: int = 20) -> bool:
    res = LAST_SYNC.get((client_id, tool))
    return not res or (utcnow() - res["at"]) > dt.timedelta(minutes=minutes)
