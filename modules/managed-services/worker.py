"""Sync worker: polls every configured tool for every mapped client on an
interval. Idles when the module is disabled. Run as its own container."""
from __future__ import annotations

import logging
import time

from app.config import settings
from app.db import SessionLocal, init_db
from app import provision
from app.sync import sync_all

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("worker")


def main() -> None:
    init_db()
    log.info("managed services sync worker up; interval %ss", settings.sync_interval_seconds)
    while True:
        if settings.module_enabled:
            db = SessionLocal()
            try:
                if provision.configured():
                    try:
                        log.info("platform pull: %s", provision.pull(db))
                    except provision.ProvisionError as e:
                        log.warning("platform pull failed: %s", e)
                counts = sync_all(db)
                log.info("sync: %s", counts)
            except Exception:  # noqa: BLE001
                log.exception("sync pass failed")
            finally:
                db.close()
        else:
            log.info("module disabled; idling")
        time.sleep(max(60, settings.sync_interval_seconds))


if __name__ == "__main__":
    main()
