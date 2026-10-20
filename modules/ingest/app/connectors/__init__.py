"""Pull connectors: read a client's own tool over its API on a schedule.

A puller is a class registered for one mapper key. The runner builds it with the
connector's non-secret config, its decrypted credentials, its cursor and an httpx
client, and iterates `pages()`. Each page is a list of raw vendor records plus the
cursor to store once that page is safely ingested. The runner ingests the page,
saves the cursor, commits, and moves on, so a crash mid-run repeats at most one page,
and duplicate records are dropped by the pipeline's dedupe key.

Rules every puller follows:

- Credentials arrive as a dict and are only ever placed in request headers or token
  exchanges. They never appear in an exception message, a log line, the cursor or a
  ConnectorError. Raise ConnectorError with a short safe reason ("HTTP 401 from the
  Graph API", "token exchange refused").
- First run with no cursor looks back FIRST_LOOKBACK (24 hours by default) and no
  further, so connecting a client never floods the pipeline with history. A backfill
  is a separate, deliberate action.
- Respect rate limits: on 429 honour Retry-After up to 60 seconds once, then stop the
  run with ConnectorError so the next scheduled run continues from the cursor.
- At most MAX_PAGES pages per run.
- Every outbound URL comes from config the operator set or the vendor's documented
  base URL. A puller never follows a URL out of a response to a different host.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import time
from typing import Iterator

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import mappers, pipeline
from ..config import settings
from ..db import Connector, ConnectorRun, utcnow

log = logging.getLogger(__name__)

MAX_PAGES = 50
FIRST_LOOKBACK = dt.timedelta(hours=24)
USER_AGENT = "VendettaSOC-Ingest/1.0"


class ConnectorError(Exception):
    """A safe, secret-free reason a run stopped."""


class Puller:
    """Base class. Subclasses set `source` and `spec`, and implement pages()."""
    source: str = ""
    # What the console asks for when a connector is added: credential keys (secret)
    # and config keys (not secret), each {key: help text}.
    spec: dict = {"credentials": {}, "config": {}}

    def __init__(self, config: dict, credentials: dict, cursor: dict, http: httpx.Client,
                 now: dt.datetime | None = None):
        self.config = config or {}
        self.credentials = credentials or {}
        self.cursor = dict(cursor or {})
        self.http = http
        self.now = now or utcnow()

    # helpers for subclasses
    def since(self, key: str = "since") -> dt.datetime:
        v = self.cursor.get(key)
        if v:
            try:
                d = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
            except ValueError:
                pass
        return self.now - FIRST_LOOKBACK

    def need(self, *keys: str, where: str = "credentials") -> None:
        src = self.credentials if where == "credentials" else self.config
        missing = [k for k in keys if not str(src.get(k) or "").strip()]
        if missing:
            raise ConnectorError(f"missing {where}: {', '.join(missing)}")

    def request(self, method: str, url: str, **kw) -> httpx.Response:
        """One HTTP call with a single Retry-After honour on 429 and safe errors."""
        for attempt in (1, 2):
            try:
                r = self.http.request(method, url, **kw)
            except httpx.HTTPError as e:
                raise ConnectorError(f"{type(e).__name__} calling {httpx.URL(url).host}") from None
            if r.status_code == 429 and attempt == 1:
                try:
                    wait = min(60.0, float(r.headers.get("Retry-After") or 5))
                except ValueError:
                    wait = 5.0
                time.sleep(wait if not getattr(self, "no_sleep", False) else 0)
                continue
            if r.status_code >= 400:
                raise ConnectorError(f"HTTP {r.status_code} from {httpx.URL(url).host}")
            return r
        raise ConnectorError(f"rate limited by {httpx.URL(url).host}")

    def pages(self) -> Iterator[tuple[list[dict], dict]]:  # pragma: no cover - abstract
        raise NotImplementedError


PULLERS: dict[str, type[Puller]] = {}


def puller(cls: type[Puller]) -> type[Puller]:
    if not cls.source:
        raise RuntimeError("puller without source")
    if cls.source in PULLERS:
        raise RuntimeError(f"puller {cls.source} registered twice")
    PULLERS[cls.source] = cls
    return cls


_LOADED = False


def _load() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    import importlib
    import pkgutil
    for info in pkgutil.iter_modules(__path__):
        if not info.name.startswith("_"):
            importlib.import_module(f"{__name__}.{info.name}")


def get(source: str) -> type[Puller] | None:
    _load()
    return PULLERS.get(source)


def catalog() -> list[dict]:
    """Every source the module can take, with the doors it supports."""
    _load()
    out = []
    for m in mappers.all_mappers():
        p = PULLERS.get(m.key)
        doors = set(m.doors) | ({"pull"} if p else set())
        out.append({"key": m.key, "name": m.name, "vendor": m.vendor, "product": m.product, "family": m.family,
                    "classes": list(m.classes), "doors": sorted(doors), "detection": m.detection,
                    "spec": p.spec if p else {"credentials": {}, "config": {}}})
    return out


def credentials_of(c: Connector) -> dict:
    if not c.credentials:
        return {}
    try:
        v = json.loads(c.credentials)
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def run(db: Session, c: Connector, transport: httpx.BaseTransport | None = None, trigger: str = "schedule",
        now: dt.datetime | None = None) -> dict:
    """Run one pull connector to the end of its data or MAX_PAGES. Never raises for a
    vendor problem: the run is recorded with its error and the cursor stays at the
    last fully ingested page."""
    cls = get(c.source)
    run_row = ConnectorRun(connector_id=c.id, trigger=trigger)
    db.add(run_row)
    c.last_run_at = utcnow()
    db.commit()
    totals = {"received": 0, "stored": 0, "duplicates": 0, "rejected": 0, "pages": 0}
    error = ""
    try:
        if cls is None:
            raise ConnectorError(f"{c.source} has no pull connector; deliver it by push or bucket")
        with httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0), transport=transport,
                          headers={"User-Agent": USER_AGENT}, follow_redirects=False) as http:
            p = cls(dict(c.config or {}), credentials_of(c), dict(c.cursor or {}), http, now=now)
            if transport is not None:
                p.no_sleep = True
            for records, cursor in p.pages():
                counts = pipeline.ingest_records(db, c, records, trigger=trigger)
                for k in ("received", "stored", "duplicates", "rejected"):
                    totals[k] += counts[k]
                c.cursor = dict(cursor or {})
                db.commit()
                totals["pages"] += 1
                if totals["pages"] >= MAX_PAGES:
                    break
    except ConnectorError as e:
        error = str(e)[:500]
    except pipeline.TenantError as e:
        error = str(e)[:500]
    except Exception as e:  # noqa: BLE001 - never leak a message that might carry a secret
        error = f"unexpected {type(e).__name__}"
        log.exception("connector %s (%s) failed", c.id, c.source)
    db.rollback()
    run_row = db.get(ConnectorRun, run_row.id)
    c = db.get(Connector, c.id)
    run_row.finished_at = utcnow()
    run_row.ok = not error
    run_row.error = error
    run_row.received, run_row.stored = totals["received"], totals["stored"]
    run_row.duplicates, run_row.rejected = totals["duplicates"], totals["rejected"]
    c.last_error = error
    c.last_received = totals["received"]
    if not error:
        c.last_ok_at = run_row.finished_at
    db.commit()
    return {"ok": not error, "error": error, **totals}


def due(db: Session, now: dt.datetime | None = None) -> list[Connector]:
    now = now or utcnow()
    _load()
    out = []
    for c in db.execute(select(Connector).where(Connector.enabled.is_(True))).scalars().all():
        if c.source not in PULLERS:
            continue
        every = int(c.interval_seconds or settings.connector_interval_seconds or 300)
        if c.last_run_at is None or (now - c.last_run_at).total_seconds() >= every:
            out.append(c)
    return out


def run_due(db: Session) -> dict:
    ran = ok = 0
    for c in due(db):
        res = run(db, c)
        ran += 1
        ok += int(res["ok"])
    return {"ran": ran, "ok": ok}


def start_scheduler(session_factory) -> None:
    interval = int(settings.connector_interval_seconds or 0)
    if interval <= 0:
        return

    def loop():
        while True:
            time.sleep(min(60, interval))
            db = session_factory()
            try:
                run_due(db)
            except Exception:  # noqa: BLE001
                log.exception("connector round failed")
            finally:
                db.close()

    threading.Thread(target=loop, name="ingest-connectors", daemon=True).start()
