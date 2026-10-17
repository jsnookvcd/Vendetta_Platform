"""Worker-polled request tables.

The web container queues long or Tor-bound work by inserting a row into a table
built on db.WorkerRequestMixin; the worker claims pending rows on its next poll,
runs them and records the result. The same functions serve every such table:
run_requests ("Run now" on the Connectors page) today, and search_requests for
live Tor search later. A row moves pending -> running -> done | failed.

Claims use SELECT ... FOR UPDATE SKIP LOCKED so two pollers never take the same
row."""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Callable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import utcnow

log = logging.getLogger(__name__)

PENDING, RUNNING, DONE, FAILED = "pending", "running", "done", "failed"


def enqueue(db: Session, model, requested_by: str, payload: dict | None = None):
    req = model(status=PENDING, requested_by=requested_by[:320], payload=payload or {})
    db.add(req)
    db.commit()
    return req


def pending(db: Session, model, where=None) -> list:
    q = select(model).where(model.status.in_((PENDING, RUNNING)))
    if where is not None:
        q = q.where(where)
    return list(db.execute(q.order_by(model.requested_at)).scalars().all())


def claim(db: Session, model, limit: int = 10, accept: Callable[[Any], bool] | None = None) -> list:
    """Mark up to `limit` pending rows running and return them. Rows `accept`
    rejects stay pending for a later poll."""
    rows = db.execute(
        select(model).where(model.status == PENDING).order_by(model.requested_at)
        .limit(limit).with_for_update(skip_locked=True)
    ).scalars().all()
    out = []
    now = utcnow()
    for r in rows:
        if accept is not None and not accept(r):
            continue
        r.status = RUNNING
        r.started_at = now
        out.append(r)
    db.commit()
    return out


def finish(db: Session, req, ok: bool, result: dict | None = None, error: str = "") -> None:
    req.status = DONE if ok else FAILED
    req.finished_at = utcnow()
    req.result = result or {}
    req.error = (error or "")[:2000]
    db.add(req)
    db.commit()


def drain(db: Session, model, handler: Callable[[Any], dict | None], limit: int = 10,
          accept: Callable[[Any], bool] | None = None) -> int:
    """Claim pending rows and run `handler(row)` on each. The handler returns a
    result dict; an exception marks the row failed with the error text."""
    n = 0
    for req in claim(db, model, limit=limit, accept=accept):
        try:
            result = handler(req) or {}
            ok = bool(result.pop("ok", True)) if isinstance(result, dict) else True
            err = result.pop("error", "") if isinstance(result, dict) else ""
            finish(db, req, ok, result, err)
        except Exception as e:  # noqa: BLE001
            log.exception("request %s failed", req.id)
            db.rollback()
            finish(db, req, False, {}, f"{type(e).__name__}: {e}")
        n += 1
    return n


def fail_interrupted(db: Session, model) -> int:
    """At worker start, rows left running by a previous process can never finish."""
    rows = db.execute(select(model).where(model.status == RUNNING)).scalars().all()
    for r in rows:
        r.status = FAILED
        r.finished_at = utcnow()
        r.error = "worker restarted before this request finished"
    db.commit()
    return len(rows)


def prune(db: Session, model, days: int) -> int:
    cutoff = utcnow() - dt.timedelta(days=days)
    res = db.execute(delete(model).where(model.status.in_((DONE, FAILED)), model.requested_at < cutoff))
    db.commit()
    return res.rowcount or 0
