"""Background schedules: sealing, daily anchors, hot-store retention and the bucket
door. Connector polling and streaming detection keep their own loops in
connectors/__init__.py and stream.py. WORKER_ROLES decides which loops this process
starts, so the web, worker and stream services on ECS can split the work while
docker compose runs everything in one process.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import connectors, evidence, pipeline, receipts, sinks, stream
from .config import settings
from .db import Anchor, Batch, Connector, utcnow

log = logging.getLogger(__name__)

LAST: dict = {"seal": None, "seal_detail": "never run", "anchor": None, "anchor_detail": "never run",
              "bucket": None, "bucket_detail": "off"}


def roles() -> set[str]:
    raw = {r.strip().lower() for r in (settings.worker_roles or "").split(",") if r.strip()}
    if "all" in raw:
        return {"connectors", "stream", "seal", "bucket"}
    return raw


# ---------------------------------------------------------------- anchors
def heads(db: Session) -> dict:
    out = {}
    for b in db.execute(select(Batch).order_by(Batch.tenant, Batch.batch_seq)).scalars():
        out[b.tenant] = {"batch_seq": b.batch_seq, "batch_hash": b.batch_hash, "sealed_at": b.sealed_at.isoformat()}
    return out


def anchor(db: Session, now: dt.datetime | None = None) -> Anchor | None:
    """Sign the current head of every tenant's chain and write it to WORM storage.
    The anchor is what makes history fixed: after it exists, rewriting any earlier
    batch would require the anchor (in an Object Lock bucket Vendetta cannot delete)
    to disagree."""
    now = now or utcnow()
    h = heads(db)
    if not h:
        return None
    doc = {"scheme": "vcd-telemetry-anchor-v1", "created_at": now.isoformat(), "key_id": evidence.key_id(),
           "public_key": evidence.public_key_hex(), "tenants": h}
    digest = receipts.sha256_hex(receipts.canonical(doc))
    a = Anchor(created_at=now, digest=digest, document=doc, signature=evidence.sign_bytes(bytes.fromhex(digest)))
    body = json.dumps({"document": doc, "digest": digest, "signature": a.signature}, indent=2).encode()
    a.stored_at = sinks.put_anchor(f"telemetry-anchors/{now:%Y/%m/%d}/{digest}.json", body)
    db.add(a)
    db.execute(Batch.__table__.update().where(Batch.anchored_at.is_(None), Batch.sealed_at <= now)
               .values(anchored_at=now))
    db.commit()
    return a


def anchor_due(db: Session, now: dt.datetime | None = None) -> bool:
    now = now or utcnow()
    last = db.execute(select(Anchor).order_by(Anchor.created_at.desc()).limit(1)).scalar_one_or_none()
    return last is None or (now - last.created_at) >= dt.timedelta(hours=24)


# ---------------------------------------------------------------- bucket door
def bucket_sink(session_factory):
    """Route key = connector id. A connector takes bucket delivery when its config
    names the bucket (and optionally a prefix)."""
    def sink(route: str, records: list) -> None:
        db = session_factory()
        try:
            c = db.get(Connector, route)
            if c is None or not c.enabled:
                raise RuntimeError("bucket route points at no enabled connector")
            pipeline.ingest_records(db, c, records, trigger="bucket")
        finally:
            db.close()
    return sink


def bucket_routes(db: Session) -> dict[str, str]:
    out = {}
    for c in db.execute(select(Connector).where(Connector.enabled.is_(True))).scalars():
        b = str((c.config or {}).get("bucket") or "").strip()
        if b:
            prefix = str((c.config or {}).get("prefix") or "").strip().lstrip("/")
            out[f"{b}/{prefix}" if prefix else b] = c.id
    return out


def bucket_once(session_factory) -> dict:
    from .connectors.bucket import BucketReader
    allowed = [b.strip() for b in settings.bucket_allowlist.split(",") if b.strip()]
    if not (settings.bucket_feed_queue_url and allowed):
        return {"off": True}
    db = session_factory()
    try:
        routes = bucket_routes(db)
    finally:
        db.close()
    reader = BucketReader.from_boto3(settings.bucket_feed_queue_url, allowed, bucket_sink(session_factory),
                                     region=settings.aws_region, routes=routes)
    return reader.poll_once()


# ---------------------------------------------------------------- loops
def _loop(name: str, every: int, fn) -> None:
    def run():
        while True:
            time.sleep(every)
            try:
                fn()
            except Exception:  # noqa: BLE001
                log.exception("%s loop failed", name)
    threading.Thread(target=run, name=f"ingest-{name}", daemon=True).start()


def start(session_factory) -> None:
    r = roles()
    if "connectors" in r:
        connectors.start_scheduler(session_factory)
    if "stream" in r:
        stream.start_scheduler(session_factory)
    if "seal" in r and int(settings.seal_interval_seconds or 0) > 0:
        def seal_round():
            db = session_factory()
            try:
                LAST["seal"] = utcnow()
                LAST["seal_detail"] = json.dumps(pipeline.seal(db))
                if anchor_due(db):
                    a = anchor(db)
                    LAST["anchor"] = utcnow()
                    LAST["anchor_detail"] = (a.stored_at or "stored in the database") if a else "nothing sealed yet"
                pipeline.purge(db)
            finally:
                db.close()
        _loop("seal", int(settings.seal_interval_seconds), seal_round)
    if "bucket" in r and settings.bucket_feed_queue_url:
        def bucket_round():
            LAST["bucket"] = utcnow()
            LAST["bucket_detail"] = json.dumps(bucket_once(session_factory), default=str)
        _loop("bucket", 20, bucket_round)


def state() -> dict:
    def iso(v):
        return v.isoformat() if v else None
    return {"roles": sorted(roles()), "seal_at": iso(LAST["seal"]), "seal_detail": LAST["seal_detail"],
            "anchor_at": iso(LAST["anchor"]), "anchor_detail": LAST["anchor_detail"],
            "bucket_at": iso(LAST["bucket"]), "bucket_detail": LAST["bucket_detail"]}
