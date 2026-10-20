"""The pipeline end to end on Postgres: tenant stamping, dedupe, rejection, sealing,
proofs that verify offline, determinism of normalization, and tamper detection on
the stored chain."""
import datetime as dt
import json

import pytest
from sqlalchemy import select, update

from app import mappers, pipeline, receipts
from app.config import settings
from app.db import Batch, Connector, Event, Rejected, SessionLocal
from helpers import make_client, make_connector, signin


@pytest.fixture()
def acme(fresh_db):
    c = make_client()
    return c, make_connector(c)


def _ingest(conn, records):
    db = SessionLocal()
    try:
        return pipeline.ingest_records(db, db.get(Connector, conn.id), records)
    finally:
        db.close()


def test_tenant_comes_from_the_connector_never_the_record(acme):
    c, conn = acme
    rec = signin(1, tenant_uid="plat-evil", metadata={"tenant_uid": "plat-evil"})
    assert _ingest(conn, [rec])["stored"] == 1
    ev = SessionLocal().execute(select(Event)).scalar_one()
    assert ev.tenant == "plat-acme" and ev.client_id == c.id
    assert ev.event["metadata"]["tenant_uid"] == "plat-acme"
    assert ev.event["unmapped"]["tenant_id"] == "plat-acme"
    assert ev.event["metadata"]["log_name"] == "entra_signins"


def test_duplicates_by_vendor_id_are_dropped(acme):
    _, conn = acme
    assert _ingest(conn, [signin(1), signin(2)])["stored"] == 2
    out = _ingest(conn, [signin(1), signin(2), signin(3)])
    assert out == {"received": 3, "stored": 1, "duplicates": 2, "rejected": 0, "skipped": 0}
    db = SessionLocal()
    assert db.get(Connector, conn.id).events_total == 3


def test_same_vendor_id_in_two_tenants_is_two_events(fresh_db):
    a = make_connector(make_client())
    b = make_connector(make_client(name="Beta", pid="plat-beta", domains="beta.example"))
    assert _ingest(a, [signin(1)])["stored"] == 1
    assert _ingest(b, [signin(1)])["stored"] == 1


def test_malformed_and_oversized_records_are_rejected_and_hashed(acme, monkeypatch):
    _, conn = acme
    monkeypatch.setattr(settings, "max_record_bytes", 2000)
    out = _ingest(conn, [{"id": "x"}, signin(1, padding="z" * 3000), "not an object", signin(2)])
    assert out["stored"] == 1 and out["rejected"] == 3
    rows = SessionLocal().execute(select(Rejected)).scalars().all()
    assert {r.reason.split(":")[0] for r in rows} >= {"mapping", "record larger than 2000 bytes"}
    assert all(len(r.raw_sha256) == 64 and len(r.sample) <= 2048 for r in rows)


def test_inactive_client_stores_nothing(fresh_db):
    conn = make_connector(make_client(active=False))
    with pytest.raises(pipeline.TenantError):
        _ingest(conn, [signin(1)])
    assert SessionLocal().execute(select(Event)).first() is None


def test_seal_proof_verifies_offline_with_the_raw_record(acme):
    _, conn = acme
    _ingest(conn, [signin(i, user=f"u{i}@acme.example") for i in range(7)])
    db = SessionLocal()
    summ = pipeline.seal(db)
    assert summ == {"tenants": 1, "batches": 1, "events": 7}
    for ev in db.execute(select(Event)).scalars():
        proof = pipeline.proof(db, ev)
        out = receipts.verify_proof(json.loads(json.dumps(proof)), json.loads(ev.raw))
        assert out["ok"], out
    b = db.execute(select(Batch)).scalar_one()
    assert b.header["tenant"] == "plat-acme" and b.size == 7 and b.prev_batch_hash == receipts.GENESIS


def test_batches_chain_and_split_at_the_size_limit(acme, monkeypatch):
    _, conn = acme
    monkeypatch.setattr(settings, "seal_max_events", 3)
    _ingest(conn, [signin(i) for i in range(8)])
    db = SessionLocal()
    assert pipeline.seal(db) == {"tenants": 1, "batches": 3, "events": 8}
    out = pipeline.verify_tenant(db, "plat-acme")
    assert out["ok"] and out["verified"] == 3 and out["events_unsealed"] == 0
    seqs = [b.batch_seq for b in db.execute(select(Batch).order_by(Batch.batch_seq)).scalars()]
    assert seqs == [1, 2, 3]


def test_tenants_have_independent_chains(fresh_db):
    a = make_connector(make_client())
    b = make_connector(make_client(name="Beta", pid="plat-beta", domains="beta.example"))
    _ingest(a, [signin(1)])
    _ingest(b, [signin(1), signin(2)])
    db = SessionLocal()
    pipeline.seal(db)
    heads = {x.tenant: x for x in db.execute(select(Batch)).scalars()}
    assert set(heads) == {"plat-acme", "plat-beta"}
    assert heads["plat-acme"].prev_batch_hash == heads["plat-beta"].prev_batch_hash == receipts.GENESIS
    assert heads["plat-beta"].size == 2


def test_normalization_is_reproducible_from_the_archived_raw(acme):
    """Anyone can re-run the open mapper on the archived raw record and get the exact
    event the receipt commits to."""
    _, conn = acme
    _ingest(conn, [signin(5, ok=False)])
    ev = SessionLocal().execute(select(Event)).scalar_one()
    again = pipeline.stamp(mappers.normalize("entra_signins", json.loads(ev.raw)), ev.tenant, ev.source)
    assert receipts.event_hash(again) == ev.event_sha256
    assert receipts.raw_hash(json.loads(ev.raw)) == ev.raw_sha256


def test_editing_a_stored_event_breaks_its_proof(acme):
    _, conn = acme
    _ingest(conn, [signin(1), signin(2)])
    db = SessionLocal()
    pipeline.seal(db)
    ev = db.execute(select(Event).order_by(Event.seq)).scalars().first()
    doctored = json.loads(ev.event_text)
    doctored["message"] = "nothing happened here"
    db.execute(update(Event).where(Event.seq == ev.seq).values(event_text=json.dumps(doctored)))
    db.commit()
    db.expire_all()
    ev = db.get(Event, ev.seq)
    assert receipts.verify_proof(pipeline.proof(db, ev))["reason"] == "the event does not match its recorded hash"


def test_rewriting_a_batch_is_caught_by_chain_verification(acme, monkeypatch):
    _, conn = acme
    monkeypatch.setattr(settings, "seal_max_events", 2)
    _ingest(conn, [signin(i) for i in range(4)])
    db = SessionLocal()
    pipeline.seal(db)
    first = db.execute(select(Batch).where(Batch.batch_seq == 1)).scalar_one()
    db.execute(update(Batch).where(Batch.id == first.id).values(leaves=first.leaves[:32] + b"\x00" * 32))
    db.commit()
    out = pipeline.verify_tenant(db, "plat-acme")
    assert out["ok"] is False and "do not match its root" in out["reason"]


def test_unsealed_event_has_no_proof_yet(acme):
    _, conn = acme
    _ingest(conn, [signin(1)])
    db = SessionLocal()
    assert pipeline.proof(db, db.execute(select(Event)).scalar_one()) is None


def test_purge_by_arrival_keeps_unsealed_undetected_and_recent(acme):
    """Retention runs on when an event arrived, never on the vendor's own time, and
    an event is purged only once it is both sealed and evaluated by detection."""
    _, conn = acme
    _ingest(conn, [signin(1, at="2001-01-01T00:00:00Z"), signin(2)])
    db = SessionLocal()
    now = dt.datetime.now(dt.timezone.utc)
    assert pipeline.purge(db, now) == 0                      # old-dated but just arrived
    pipeline.seal(db, now)
    later = now + dt.timedelta(days=31)
    assert pipeline.purge(db, later) == 0                    # sealed but not yet evaluated
    from app import stream
    stream.run(db)
    _ingest(conn, [signin(3)])
    assert pipeline.purge(db, later) == 2
    assert [e.dedupe_key for e in db.execute(select(Event)).scalars()] == ["si-3"]
    assert db.execute(select(Batch)).scalar_one().size == 2  # leaves survive the purge
