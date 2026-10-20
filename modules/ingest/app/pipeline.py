"""The ingest pipeline: every record from every door goes through here.

ingest_records() takes raw vendor records for one connector and, for each record:

1. hashes it as received (raw_sha256), before anything parses it;
2. normalizes it to OCSF with the connector's mapper;
3. stamps the tenant from the connector, never from the record;
4. hashes the normalized event (event_sha256);
5. stores it once, dropping duplicates by the vendor's record id;
6. hands new events to the configured sinks (Kinesis, raw archive, OpenSearch).

seal() turns each tenant's unsealed events into a signed Merkle batch chained to the
tenant's previous batch, and proof() rebuilds an event's inclusion proof from the
stored leaf hashes. Normalization is deterministic and carries no processing time,
so anyone can re-run the open mapper over the archived raw record and get the same
event hash the receipt commits to.
"""
from __future__ import annotations

import datetime as dt
import logging
import zlib

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from . import evidence, mappers, ocsf, receipts, sinks
from .config import settings
from .db import Batch, Client, Connector, Event, Rejected, utcnow

log = logging.getLogger(__name__)

LOG_PROVIDER = "Vendetta Telemetry Ingest"


class TenantError(Exception):
    """The connector's client is inactive or has no platform id; nothing is stored."""


def tenant_of(db: Session, connector: Connector) -> tuple[str, Client]:
    c = db.get(Client, connector.client_id)
    if c is None or not c.active or not (c.platform_client_id or "").strip():
        raise TenantError("connector's client is not active on the platform")
    return c.platform_client_id, c


def stamp(ev: dict, tenant: str, source: str) -> dict:
    md = ev.setdefault("metadata", {})
    md["tenant_uid"] = tenant
    md["log_name"] = source
    md["log_provider"] = LOG_PROVIDER
    ev.setdefault("unmapped", {})["tenant_id"] = tenant
    return ev


def _dt(ms: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc)


def ingest_records(db: Session, connector: Connector, records: list, trigger: str = "pull") -> dict:
    """Normalize and store records for one connector. Commits. Returns counts."""
    tenant, client = tenant_of(db, connector)
    m = mappers.get(connector.source)
    if m is None:
        raise ValueError(f"no mapper for {connector.source}")
    received = len(records)
    rows: list[dict] = []
    rejected = skipped = 0
    for raw in records:
        try:
            body = receipts.canonical(raw)
        except (TypeError, ValueError):
            body = repr(raw).encode("utf-8", "replace")
        raw_sha = receipts.sha256_hex(body)
        reason = ""
        ev = None
        if len(body) > settings.max_record_bytes:
            reason = f"record larger than {settings.max_record_bytes} bytes"
        else:
            try:
                ev = mappers.normalize(connector.source, raw)
                if ev is None:
                    skipped += 1
                    continue
            except ocsf.MappingError as e:
                reason = f"mapping: {e}"[:300]
            except Exception as e:  # noqa: BLE001 - a mapper bug must not stop the feed
                reason = f"mapper error: {type(e).__name__}"
                log.exception("mapper %s failed", connector.source)
        if reason:
            rejected += 1
            db.add(Rejected(connector_id=connector.id, tenant=tenant, reason=reason, raw_sha256=raw_sha,
                            sample=body[:2048].decode("utf-8", "replace")))
            continue
        stamp(ev, tenant, connector.source)
        ev_sha = receipts.event_hash(ev)
        s = ocsf.summary(ev)
        uid = ""
        try:
            uid = (m.uid(raw) or "").strip()
        except Exception:  # noqa: BLE001
            uid = ""
        rows.append({
            "id": evidence_id(), "tenant": tenant, "client_id": client.id, "connector_id": connector.id,
            "source": connector.source, "class_uid": ev["class_uid"], "time": _dt(ev["time"]),
            "received_at": utcnow(), "severity_id": int(ev.get("severity_id") or 0), "host": s["host"],
            "user": s["user"], "src_ip": s["src_ip"], "title": s["title"], "dedupe_key": (uid or raw_sha)[:200],
            "raw_sha256": raw_sha, "event_sha256": ev_sha, "event": ev, "raw": body.decode("utf-8", "replace"),
        })
    stored_rows: list[dict] = []
    if rows:
        # One statement; duplicates (same tenant, source and vendor id) are dropped.
        stmt = pg_insert(Event).values(rows).on_conflict_do_nothing(constraint="uq_event_dedupe") \
            .returning(Event.id)
        kept = set(db.execute(stmt).scalars().all())
        stored_rows = [r for r in rows if r["id"] in kept]
    duplicates = len(rows) - len(stored_rows)
    connector.events_total = (connector.events_total or 0) + len(stored_rows)
    connector.rejected_total = (connector.rejected_total or 0) + rejected
    if stored_rows:
        newest = max(r["time"] for r in stored_rows)
        if connector.newest_event_at is None or newest > connector.newest_event_at:
            connector.newest_event_at = newest
    db.commit()
    if stored_rows:
        sinks.publish(stored_rows)
    return {"received": received, "stored": len(stored_rows), "duplicates": duplicates, "rejected": rejected,
            "skipped": skipped}


def evidence_id() -> str:
    from .db import new_id
    return new_id()


# ---------------------------------------------------------------- sealing
def _lock_tenant(db: Session, tenant: str) -> None:
    # Serializes sealing per tenant across workers and replicas on one database.
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": zlib.crc32(f"seal:{tenant}".encode())})


def seal_tenant(db: Session, tenant: str, now: dt.datetime | None = None) -> Batch | None:
    """Seal up to SEAL_MAX_EVENTS of one tenant's unsealed events. Commits."""
    now = now or utcnow()
    _lock_tenant(db, tenant)
    rows = db.execute(
        select(Event.seq, Event.id, Event.raw_sha256, Event.event_sha256, Event.time)
        .where(Event.tenant == tenant, Event.batch_id.is_(None))
        .order_by(Event.seq).limit(max(1, int(settings.seal_max_events)))).all()
    if not rows:
        db.commit()
        return None
    prev = db.execute(select(Batch).where(Batch.tenant == tenant).order_by(Batch.batch_seq.desc()).limit(1)
                      ).scalar_one_or_none()
    leaves = [receipts.leaf_hash(r.raw_sha256, r.event_sha256) for r in rows]
    times = [r.time for r in rows]
    header = receipts.make_header(
        tenant=tenant, batch_seq=(prev.batch_seq + 1) if prev else 1, leaves=leaves,
        first_seq=rows[0].seq, last_seq=rows[-1].seq,
        first_event_time=min(times).isoformat(), last_event_time=max(times).isoformat(),
        sealed_at=now.isoformat(), prev_batch_hash=prev.batch_hash if prev else receipts.GENESIS,
        key_id=evidence.key_id())
    bhash = receipts.header_hash(header)
    b = Batch(tenant=tenant, batch_seq=header["batch_seq"], size=header["size"], first_seq=header["first_seq"],
              last_seq=header["last_seq"], sealed_at=now, header=header, root=header["root"],
              prev_batch_hash=header["prev_batch_hash"], batch_hash=bhash,
              signature=evidence.sign_bytes(bytes.fromhex(bhash)), key_id=header["key_id"],
              public_key=evidence.public_key_hex(), leaves=b"".join(leaves))
    db.add(b)
    db.flush()
    db.execute(update(Event), [{"seq": r.seq, "batch_id": b.id, "leaf_index": i} for i, r in enumerate(rows)])
    db.commit()
    sinks.publish_batch(b.record())
    return b


def seal(db: Session, now: dt.datetime | None = None) -> dict:
    tenants = db.execute(select(Event.tenant).where(Event.batch_id.is_(None)).distinct()).scalars().all()
    sealed = events = 0
    for t in tenants:
        while True:
            b = seal_tenant(db, t, now)
            if b is None:
                break
            sealed += 1
            events += b.size
            if b.size < settings.seal_max_events:
                break
    return {"tenants": len(tenants), "batches": sealed, "events": events}


# ---------------------------------------------------------------- proofs
def proof(db: Session, ev: Event) -> dict | None:
    """The inclusion proof for one sealed event, in the shape receipts.verify_proof
    reads. None while the event is still waiting for its seal."""
    if not ev.batch_id:
        return None
    b = db.get(Batch, ev.batch_id)
    if b is None:
        return None
    leaves = [b.leaves[i:i + 32] for i in range(0, len(b.leaves), 32)]
    rcpt = {"tenant": ev.tenant, "raw_sha256": ev.raw_sha256, "event_sha256": ev.event_sha256,
            "leaf_index": ev.leaf_index, "audit_path": receipts.audit_path(leaves, ev.leaf_index)}
    event = dict(ev.event)
    return {"scheme": receipts.SCHEME, "event_id": ev.id, "event": event, "receipt": rcpt,
            "batch": b.record(),
            "verify": "python receipts.py proof.json [raw.json]  (receipts.py is published with the platform)"}


def chain(db: Session, tenant: str, since_seq: int = 1, limit: int = 1000) -> list[dict]:
    rows = db.execute(select(Batch).where(Batch.tenant == tenant, Batch.batch_seq >= since_seq)
                      .order_by(Batch.batch_seq).limit(limit)).scalars().all()
    return [b.record() for b in rows]


def verify_tenant(db: Session, tenant: str) -> dict:
    """Re-verify a tenant's whole chain from the database: every header, signature and
    link, and every batch's stored leaves against its signed root."""
    out = receipts.verify_chain(chain(db, tenant, 1, 10_000_000))
    if not out["ok"]:
        return out
    for b in db.execute(select(Batch).where(Batch.tenant == tenant).order_by(Batch.batch_seq)).scalars():
        leaves = [b.leaves[i:i + 32] for i in range(0, len(b.leaves), 32)]
        if receipts.merkle_root(leaves).hex() != b.root or len(leaves) != b.size:
            return {**out, "ok": False, "reason": f"stored leaves of batch {b.batch_seq} do not match its root",
                    "broken_at": b.batch_seq}
    out["events_unsealed"] = db.scalar(select(func.count()).select_from(Event).where(
        Event.tenant == tenant, Event.batch_id.is_(None))) or 0
    return out


def purge(db: Session, now: dt.datetime | None = None) -> int:
    """Drop sealed hot-store events past retention. Batches and leaves stay."""
    now = now or utcnow()
    cutoff = now - dt.timedelta(days=max(1, int(settings.hot_retention_days)))
    res = db.execute(Event.__table__.delete().where(Event.time < cutoff, Event.batch_id.isnot(None)))
    db.commit()
    return res.rowcount or 0
