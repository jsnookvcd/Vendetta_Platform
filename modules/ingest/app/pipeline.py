"""The ingest pipeline: every record from every door goes through here.

ingest_records() takes raw vendor records for one connector and, for each record:

1. hashes it in RFC 8785 canonical form as parsed from the delivery (raw_sha256);
2. normalizes it to OCSF with the connector's mapper, then replaces NUL characters;
3. stamps the tenant from the connector, never from the record;
4. hashes the normalized event in canonical form (event_sha256) and keeps those
   exact bytes, which proofs are built from;
5. stores it once, dropping duplicates by the vendor's record id;
6. hands new events to the configured sinks (Kinesis, raw archive, OpenSearch).

A record that cannot be hashed, normalized or stored is rejected alone, with its
hash and the reason; it never fails the rest of the delivery.

seal() turns each tenant's unsealed events into a signed Merkle batch chained to the
tenant's previous batch, and proof() rebuilds an event's inclusion proof from the
stored leaf hashes. Normalization is deterministic and carries no processing time,
so anyone can re-run the open mapper over the archived raw record and get the same
event hash the receipt commits to.
"""
from __future__ import annotations

import datetime as dt
import json
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


# A record's own time may be at most this far after receipt in the queryable time
# column. The event JSON keeps the vendor's time as sent.
FUTURE_SKEW = dt.timedelta(minutes=5)
INSERT_CHUNK = 1000  # rows per INSERT; 18 columns stays far under Postgres' 65,535 parameters


def sanitize(value):
    """Part of normalization, so it is deterministic and reproducible: replace NUL,
    which Postgres text and JSONB cannot hold, with U+FFFD in every string and key.
    Lone surrogates are refused later by canonical()."""
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd") if "\x00" in value else value
    if isinstance(value, dict):
        return {sanitize(k): sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return value


def _account_mismatch(connector: Connector, raw) -> bool:
    """A CloudTrail connector bound to one AWS account refuses records from another,
    so a misrouted object in a shared bucket cannot land under the wrong client."""
    want = str((connector.config or {}).get("account_id") or "").strip()
    if not want or connector.source != "cloudtrail" or not isinstance(raw, dict):
        return False
    got = str(raw.get("recipientAccountId") or (raw.get("userIdentity") or {}).get("accountId") or "")
    return bool(got) and got != want


def _sample(body: bytes) -> str:
    return body[:2048].decode("utf-8", "replace").replace("\x00", "")


def _prepare(m, connector: Connector, tenant: str, client: Client, raw, now: dt.datetime) -> tuple[dict | None, str, str]:
    """One record to one row. Returns (row, raw_sha256, rejection reason). Every
    failure is a rejection of this record alone."""
    try:
        body = receipts.canonical(raw)
    except (ValueError, TypeError, RecursionError) as e:
        body = repr(raw)[:2048].encode("utf-8", "replace")
        return None, receipts.sha256_hex(body), f"raw: {e}"[:300]
    raw_sha = receipts.sha256_hex(body)
    if len(body) > settings.max_record_bytes:
        return None, raw_sha, f"record larger than {settings.max_record_bytes} bytes"
    if _account_mismatch(connector, raw):
        return None, raw_sha, "record is from an AWS account this connector is not bound to"
    try:
        ev = mappers.normalize(connector.source, raw)
        if ev is None:
            return None, raw_sha, ""
        ev = stamp(sanitize(ev), tenant, connector.source)
        text = receipts.canonical(ev)
        ev_sha = receipts.sha256_hex(text)
        s = ocsf.summary(ev)
    except ocsf.MappingError as e:
        return None, raw_sha, f"mapping: {e}"[:300]
    except (ValueError, TypeError, RecursionError) as e:
        return None, raw_sha, f"event: {e}"[:300]
    except Exception as e:  # noqa: BLE001 - a mapper bug must not stop the feed
        log.exception("mapper %s failed", connector.source)
        return None, raw_sha, f"mapper error: {type(e).__name__}"
    try:
        uid = (m.uid(raw) or "").strip()
    except Exception:  # noqa: BLE001
        uid = ""
    when = min(_dt(ev["time"]), now + FUTURE_SKEW)
    return {
        "id": evidence_id(), "tenant": tenant, "client_id": client.id, "connector_id": connector.id,
        "source": connector.source, "class_uid": ev["class_uid"], "time": when, "received_at": now,
        "severity_id": int(ev.get("severity_id") or 0), "host": s["host"], "user": s["user"], "src_ip": s["src_ip"],
        "title": s["title"], "dedupe_key": (uid or raw_sha)[:200], "raw_sha256": raw_sha, "event_sha256": ev_sha,
        "event": ev, "event_text": text.decode("utf-8"), "raw": body, "detected": False,
    }, raw_sha, ""


def ingest_records(db: Session, connector: Connector, records: list, trigger: str = "pull") -> dict:
    """Normalize and store records for one connector. Commits. Returns counts. A
    record that cannot be stored is rejected on its own; the rest of the delivery is
    stored."""
    tenant, client = tenant_of(db, connector)
    m = mappers.get(connector.source)
    if m is None:
        raise ValueError(f"no mapper for {connector.source}")
    now = utcnow()
    rows: list[dict] = []
    rejected = skipped = 0
    for raw in records:
        row, raw_sha, reason = _prepare(m, connector, tenant, client, raw, now)
        if row is not None:
            rows.append(row)
        elif reason:
            rejected += 1
            try:
                sample = _sample(receipts.canonical(raw))
            except (ValueError, TypeError, RecursionError):
                sample = _sample(repr(raw).encode("utf-8", "replace"))
            db.add(Rejected(connector_id=connector.id, tenant=tenant, reason=reason, raw_sha256=raw_sha,
                            sample=sample))
        else:
            skipped += 1
    stored_rows: list[dict] = []
    for i in range(0, len(rows), INSERT_CHUNK):
        chunk = rows[i:i + INSERT_CHUNK]
        # Duplicates (same tenant, source and vendor id) are dropped by the constraint.
        stmt = pg_insert(Event).values(chunk).on_conflict_do_nothing(constraint="uq_event_dedupe") \
            .returning(Event.id)
        kept = set(db.execute(stmt).scalars().all())
        stored_rows.extend(r for r in chunk if r["id"] in kept)
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
    return {"received": len(records), "stored": len(stored_rows), "duplicates": duplicates, "rejected": rejected,
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
    event = json.loads(ev.event_text)
    return {"scheme": receipts.SCHEME, "event_id": ev.id, "event": event, "receipt": rcpt,
            "batch": b.record(),
            "verify": "python receipts.py proof.json [raw.json]  (receipts.py is published with the platform)"}


def chain(db: Session, tenant: str, since_seq: int = 1, limit: int = 1000) -> list[dict]:
    # Batch.leaves is deferred: a chain export never loads the leaf hashes.
    rows = db.execute(select(Batch).where(Batch.tenant == tenant, Batch.batch_seq >= since_seq)
                      .order_by(Batch.batch_seq).limit(limit)).scalars().all()
    return [b.record() for b in rows]


def latest_anchor(db: Session, tenant: str) -> dict | None:
    """This tenant's statement from the newest anchor that covers it, in the shape
    receipts.verify_chain takes. Each statement is signed on its own and names only
    this tenant's head plus the digest of the global anchor written to WORM storage,
    so a client sees nothing about any other client."""
    from .db import Anchor
    for a in db.execute(select(Anchor).order_by(Anchor.created_at.desc()).limit(30)).scalars():
        st = (a.statements or {}).get(tenant)
        if st:
            return dict(st)
    return None


def verify_tenant(db: Session, tenant: str) -> dict:
    """Re-verify a tenant's whole chain from the database: every header, signature and
    link, and every batch's stored leaves against its signed root."""
    out = receipts.verify_chain(chain(db, tenant, 1, 10_000_000))
    if not out["ok"]:
        return out
    for b in db.execute(select(Batch).where(Batch.tenant == tenant).order_by(Batch.batch_seq)
                        .execution_options(yield_per=50)).scalars():
        leaves = [b.leaves[i:i + 32] for i in range(0, len(b.leaves), 32)]
        if receipts.merkle_root(leaves).hex() != b.root or len(leaves) != b.size:
            return {**out, "ok": False, "reason": f"stored leaves of batch {b.batch_seq} do not match its root",
                    "broken_at": b.batch_seq}
    out["events_unsealed"] = db.scalar(select(func.count()).select_from(Event).where(
        Event.tenant == tenant, Event.batch_id.is_(None))) or 0
    return out


def purge(db: Session, now: dt.datetime | None = None) -> int:
    """Drop sealed hot-store events past retention, by when they arrived (a record's
    own time is vendor-controlled). Batches and leaves stay."""
    now = now or utcnow()
    cutoff = now - dt.timedelta(days=max(1, int(settings.hot_retention_days)))
    res = db.execute(Event.__table__.delete().where(Event.received_at < cutoff, Event.batch_id.isnot(None),
                                                    Event.detected.is_(True)))
    db.commit()
    return res.rowcount or 0
