"""Collector scheduler. Runs as its own container. A job never overlaps itself; a
slow onion sweep just delays its own next run.

Every collector job comes from the registry in app/connectors.py. Each run is
recorded as a CollectorRun row. The worker also writes a heartbeat every minute,
the Tor check every ten minutes, drains "Run now" requests every minute and
prunes old run history daily."""
from __future__ import annotations

import datetime as dt
import logging
import sys
import time
from typing import Any, Callable

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import select

from . import boot, connectors, health, pipeline, work_requests
from .config import settings
from .db import CollectorRun, RunRequest, SessionLocal, init_db, utcnow
from .fetch import tor_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
log = logging.getLogger("worker")

HEARTBEAT_MINUTES = 1
TOR_CHECK_MINUTES = 10
REQUEST_POLL_MINUTES = 1
RUNNING_STALE_HOURS = 6
START_DELAY_SECONDS = 10


def _summary(result: Any) -> dict:
    if isinstance(result, dict):
        return dict(result)
    if isinstance(result, int) and not isinstance(result, bool):
        return {"count": result}
    return {}


def run_job(job_id: str, fn: Callable, *, trigger: str = "schedule", requested_by: str = "",
            check: Callable[[Any], tuple[bool, str]] | None = None) -> CollectorRun | None:
    """Run one collector and record it. The CollectorRun row is written through its
    own session so a collector that breaks its session still gets a record.
    Returns None when the module is disabled or the connector is not configured on
    a scheduled run (nothing to record)."""
    if not settings.module_enabled:
        log.info("module disabled; skipping %s", job_id)
        return None
    db = SessionLocal()
    rdb = SessionLocal()
    stats, token = pipeline.begin_stats()
    run: CollectorRun | None = None
    try:
        if check is not None:
            ok, reason = check(db)
            if not ok:
                if trigger == "schedule":
                    log.info("%s not configured: %s", job_id, reason)
                    return None
                run = CollectorRun(job_id=job_id, trigger=trigger, requested_by=requested_by,
                                   started_at=utcnow(), finished_at=utcnow(), ok=False,
                                   error=f"not configured: {reason}"[:2000])
                rdb.add(run)
                rdb.commit()
                return run
        run = CollectorRun(job_id=job_id, trigger=trigger, requested_by=requested_by, started_at=utcnow())
        rdb.add(run)
        rdb.commit()
        try:
            summary = _summary(fn(db))
            run.ok = bool(summary.pop("ok", True))
            run.error = str(summary.pop("error", "") or "")[:2000]
            run.detail = summary
        except Exception as e:  # noqa: BLE001
            log.exception("job %s failed", job_id)
            db.rollback()
            run.ok = False
            run.error = f"{type(e).__name__}: {e}"[:2000]
        run.items_new = stats.items
        run.hits_new = stats.hits
        run.finished_at = utcnow()
        rdb.commit()
        return run
    finally:
        pipeline.end_stats(token)
        db.close()
        rdb.close()


def _wrap(c: connectors.Connector) -> Callable[[], None]:
    def wrapped():
        run_job(c.job_id, c.job, check=lambda db: c.configured(db))

    wrapped.__name__ = c.job_id
    return wrapped


def heartbeat() -> None:
    db = SessionLocal()
    try:
        health.beat(db)
    finally:
        db.close()


def check_tor() -> dict:
    chk = tor_check()
    db = SessionLocal()
    try:
        return health.record_tor(db, chk)
    finally:
        db.close()


def _running(db, job_id: str) -> bool:
    cutoff = utcnow() - dt.timedelta(hours=RUNNING_STALE_HOURS)
    return db.execute(select(CollectorRun.id).where(
        CollectorRun.job_id == job_id, CollectorRun.finished_at.is_(None), CollectorRun.started_at >= cutoff
    ).limit(1)).first() is not None


def poll_requests() -> int:
    """Drain "Run now" requests. A request for a connector that is mid-run stays
    pending and is picked up on a later poll."""
    if not settings.module_enabled:
        return 0
    db = SessionLocal()
    try:
        def accept(req) -> bool:
            c = connectors.get((req.payload or {}).get("connector", ""))
            return c is None or not _running(db, c.job_id)

        def handle(req) -> dict:
            c = connectors.get((req.payload or {}).get("connector", ""))
            if c is None:
                return {"ok": False, "error": "unknown connector"}
            run = run_job(c.job_id, c.job, trigger="manual", requested_by=req.requested_by,
                          check=lambda d: c.configured(d))
            if run is None:
                return {"ok": False, "error": "module disabled"}
            return {"ok": bool(run.ok), "error": run.error, "run_id": run.id,
                    "items_new": run.items_new, "hits_new": run.hits_new}

        return work_requests.drain(db, RunRequest, handle, accept=accept)
    finally:
        db.close()


def retention() -> None:
    db = SessionLocal()
    try:
        n = health.prune_runs(db)
        m = work_requests.prune(db, RunRequest, health.RUN_RETENTION_DAYS)
        log.info("retention: pruned %d collector runs and %d requests", n, m)
    finally:
        db.close()


def _seed() -> None:
    """Daily: refresh priority groups, seed onion sources from ransomware.live PRO
    group locations and apply the disable rules (app/onion_sources.py)."""
    db = SessionLocal()
    try:
        phase2_daily(db)
    finally:
        db.close()


def _recover() -> None:
    """Close out runs and requests a previous worker process left open."""
    db = SessionLocal()
    try:
        for r in db.execute(select(CollectorRun).where(CollectorRun.finished_at.is_(None))).scalars():
            r.finished_at = utcnow()
            r.ok = False
            r.error = "worker restarted before this run finished"
        db.commit()
        work_requests.fail_interrupted(db, RunRequest)
    finally:
        db.close()


def build_scheduler(now: dt.datetime | None = None) -> BlockingScheduler:
    """A configured, unstarted scheduler. Every job gets an explicit next_run_time:
    APScheduler 3.x treats next_run_time=None as "add paused", which is how the
    leak feeds once ran only at boot (F1)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    soon = now + dt.timedelta(seconds=START_DELAY_SECONDS)
    sched = BlockingScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
    for c in connectors.CONNECTORS:
        if not c.scheduled:
            continue  # one-time backfills (ransomwatch) run only when an admin asks
        first = soon if c.run_at_start else now + dt.timedelta(minutes=c.interval_minutes)
        sched.add_job(_wrap(c), "interval", minutes=c.interval_minutes, id=c.job_id, name=c.name, next_run_time=first)
    sched.add_job(heartbeat, "interval", minutes=HEARTBEAT_MINUTES, id="heartbeat", next_run_time=now)
    sched.add_job(check_tor, "interval", minutes=TOR_CHECK_MINUTES, id="tor_check",
                  next_run_time=now + dt.timedelta(minutes=TOR_CHECK_MINUTES))
    sched.add_job(poll_requests, "interval", minutes=REQUEST_POLL_MINUTES, id="run_requests", next_run_time=soon)
    sched.add_job(retention, "interval", hours=24, id="retention", next_run_time=now + dt.timedelta(hours=1))
    sched.add_job(_seed, "interval", hours=24, id="seed", next_run_time=now + dt.timedelta(hours=24))
    add_phase2_jobs(sched, now)
    return sched


def main() -> None:
    boot.check()
    init_db()
    phase2_startup()
    _recover()
    heartbeat()
    for _ in range(20):
        chk = check_tor()
        if chk.get("is_tor"):
            log.info("tor ok, exit ip %s", chk.get("exit_ip"))
            break
        log.info("waiting for tor: %s", chk.get("error") or chk)
        heartbeat()
        time.sleep(15)
    _seed()
    sched = build_scheduler()
    log.info("scheduler started")
    sched.start()


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------- Phase 2: victim sources and priority groups
PRIORITY_REFRESH_HOURS = 24


def phase2_daily(db) -> dict:
    from . import onion_sources, priority

    out: dict = {}
    try:
        out["priority"] = priority.compute(db)
    except Exception as e:  # noqa: BLE001
        log.exception("priority refresh failed")
        db.rollback()
        out["priority_error"] = str(e)
    out["seed"] = onion_sources.seed(db)
    if not out["seed"].get("ok") and "disabled" not in out["seed"]:
        # No PRO key or the group list failed: still keep activity and the disable rules current.
        onion_sources.update_feed_activity(db)
        out["disabled"] = onion_sources.apply_disable_rules(db)
    return out


def priority_refresh() -> None:
    from . import priority

    db = SessionLocal()
    try:
        priority.compute(db)
    finally:
        db.close()


def phase2_startup() -> None:
    """Idempotent startup migration: disable the stale ransomwatch-seeded mirrors."""
    from . import onion_sources

    db = SessionLocal()
    try:
        onion_sources.migrate_ransomwatch_mirrors(db)
    finally:
        db.close()


def add_phase2_jobs(sched: BlockingScheduler, now: dt.datetime) -> None:
    sched.add_job(priority_refresh, "interval", hours=PRIORITY_REFRESH_HOURS, id="priority_refresh",
                  next_run_time=now + dt.timedelta(minutes=30))
