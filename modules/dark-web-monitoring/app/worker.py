"""Collector scheduler. Runs as its own container. Jobs never overlap; a slow
onion sweep just delays the next one."""
from __future__ import annotations

import logging
import sys
import time

from apscheduler.schedulers.blocking import BlockingScheduler

from .collectors import ct_logs, forum_crawl, hibp, leak_feeds, onion_crawl, pastes, telegram
from .config import settings
from .db import SessionLocal, init_db
from .fetch import tor_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
log = logging.getLogger("worker")


def _job(fn):
    def wrapped():
        if not settings.module_enabled:
            log.info("module disabled; skipping %s", fn.__module__)
            return
        db = SessionLocal()
        try:
            fn(db)
        except Exception:  # noqa: BLE001
            log.exception("job %s failed", fn.__module__)
        finally:
            db.close()

    wrapped.__name__ = fn.__module__
    return wrapped


def _seed():
    db = SessionLocal()
    try:
        leak_feeds.seed_onion_sources(db)
    finally:
        db.close()


def main() -> None:
    init_db()
    for _ in range(20):
        chk = tor_check()
        if chk.get("IsTor"):
            log.info("tor ok, exit ip %s", chk.get("IP"))
            break
        log.info("waiting for tor: %s", chk)
        time.sleep(15)
    _seed()
    sched = BlockingScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
    sched.add_job(_job(leak_feeds.run), "interval", minutes=settings.leak_feed_interval, next_run_time=None, id="leak_feeds")
    sched.add_job(_job(onion_crawl.run), "interval", minutes=settings.onion_crawl_interval, id="onion_crawl")
    sched.add_job(_job(forum_crawl.run), "interval", minutes=settings.forum_crawl_interval, id="forum_crawl")
    sched.add_job(_job(hibp.run), "interval", minutes=settings.hibp_interval, id="hibp")
    sched.add_job(_job(ct_logs.run), "interval", minutes=settings.ct_interval, id="ct")
    sched.add_job(_job(pastes.run), "interval", minutes=settings.paste_interval, id="pastes")
    sched.add_job(_job(telegram.run), "interval", minutes=settings.telegram_interval, id="telegram")
    sched.add_job(_seed, "interval", hours=24, id="seed")
    # Run the cheap feeds right away so the console has data on first boot.
    _job(leak_feeds.run)()
    log.info("scheduler started")
    sched.start()


if __name__ == "__main__":
    main()
