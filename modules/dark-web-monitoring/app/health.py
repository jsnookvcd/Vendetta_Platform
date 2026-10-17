"""Worker health the web container can read: the heartbeat, the latest Tor check
and the collector run log. The worker writes these through the functions here;
the Connectors page, the dashboard banner, readiness and the diagnose CLI read
them back."""
from __future__ import annotations

import datetime as dt
import os
import socket

from sqlalchemy import delete
from sqlalchemy.orm import Session

from .db import CollectorRun, WorkerState, utcnow

HEARTBEAT_KEY = "heartbeat"
TOR_KEY = "tor"
HEARTBEAT_STALE_SECONDS = 300
RUN_RETENTION_DAYS = 30


def set_state(db: Session, key: str, value: dict) -> None:
    row = db.get(WorkerState, key)
    if row is None:
        row = WorkerState(key=key)
        db.add(row)
    row.value = value
    row.updated_at = utcnow()
    db.commit()


def get_state(db: Session, key: str) -> dict | None:
    row = db.get(WorkerState, key)
    return dict(row.value or {}) if row else None


def beat(db: Session) -> None:
    set_state(db, HEARTBEAT_KEY, {"at": utcnow().isoformat(), "host": socket.gethostname(), "pid": os.getpid()})


def _parse(ts: str | None) -> dt.datetime | None:
    if not ts:
        return None
    try:
        v = dt.datetime.fromisoformat(ts)
    except ValueError:
        return None
    return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)


def heartbeat_age_seconds(db: Session, now: dt.datetime | None = None) -> int | None:
    """Seconds since the worker last beat, or None when it never has."""
    hb = get_state(db, HEARTBEAT_KEY)
    at = _parse((hb or {}).get("at"))
    if at is None:
        return None
    return max(0, int(((now or utcnow()) - at).total_seconds()))


def record_tor(db: Session, check: dict) -> dict:
    """Persist a fetch.tor_check() result in a stable shape. Reachable means the
    SOCKS proxy answered at all; is_tor means check.torproject.org saw a Tor exit."""
    err = str(check.get("error") or "")
    value = {
        "reachable": not err,
        "is_tor": bool(check.get("IsTor")),
        "exit_ip": str(check.get("IP") or ""),
        "error": err[:500],
        "checked_at": utcnow().isoformat(),
    }
    set_state(db, TOR_KEY, value)
    return value


def tor_status(db: Session) -> dict | None:
    return get_state(db, TOR_KEY)


def prune_runs(db: Session, days: int = RUN_RETENTION_DAYS) -> int:
    cutoff = utcnow() - dt.timedelta(days=days)
    res = db.execute(delete(CollectorRun).where(CollectorRun.started_at < cutoff))
    db.commit()
    return res.rowcount or 0
