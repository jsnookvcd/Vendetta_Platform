"""The case chain of custody: every timeline entry is chained and signed, the chain
verifies, and any tampering is detected."""
from app import evidence
from app.db import (Case, CaseUpdate, Client, SessionLocal, case_chain_records,
                    open_case, update_fields)


def _client():
    db = SessionLocal()
    c = Client(name="Client A")
    db.add(c); db.commit()
    return c


def test_opening_a_case_chains_the_timeline(client):
    c = _client()
    db = SessionLocal()
    case = open_case(db, c, "Ransomware on file server", actor="dan@vendettacd.io")
    recs = case_chain_records(SessionLocal(), case.id)
    assert len(recs) >= 1
    assert recs[0]["prev_hash"] == evidence.GENESIS
    assert all(r["content_hash"] and r["signature"] and r["chain_seq"] for r in recs)
    res = evidence.verify_chain(recs)
    assert res["ok"] and res["verified"] == len(recs)


def test_added_updates_extend_and_verify(client):
    c = _client()
    db = SessionLocal()
    case = open_case(db, c, "BEC wire fraud", actor="system")
    for i in range(5):
        db = SessionLocal()
        cs = db.get(Case, case.id)
        cs.updates.append(CaseUpdate(actor="analyst", kind="note", note=f"step {i}", internal_only=False))
        db.commit()
    recs = case_chain_records(SessionLocal(), case.id)
    seqs = [r["chain_seq"] for r in recs]
    assert seqs == list(range(1, len(recs) + 1))  # contiguous, 1-based
    assert evidence.verify_chain(recs)["ok"]


def test_tampering_with_a_note_is_detected(client):
    c = _client()
    db = SessionLocal()
    case = open_case(db, c, "Insider exfiltration", actor="system")
    db = SessionLocal()
    db.add(CaseUpdate(case_id=case.id, actor="analyst", kind="note",
                      note="original finding", internal_only=True))
    db.commit()
    # Simulate an attacker editing the stored note without re-signing.
    db = SessionLocal()
    u = db.execute(
        __import__("sqlalchemy").select(CaseUpdate)
        .where(CaseUpdate.case_id == case.id, CaseUpdate.note == "original finding")
    ).scalar_one()
    u.note = "doctored finding"
    db.commit()
    recs = case_chain_records(SessionLocal(), case.id)
    res = evidence.verify_chain(recs)
    assert res["ok"] is False
    assert res["broken_at"] is not None


def test_deleting_a_middle_entry_breaks_the_chain(client):
    c = _client()
    db = SessionLocal()
    case = open_case(db, c, "Case with deletion", actor="system")
    import sqlalchemy as sa
    for i in range(4):
        db = SessionLocal()
        db.add(CaseUpdate(case_id=case.id, actor="analyst", kind="note", note=f"entry {i}"))
        db.commit()
    # Remove a middle entry outright.
    db = SessionLocal()
    victim = db.execute(sa.select(CaseUpdate).where(CaseUpdate.case_id == case.id, CaseUpdate.note == "entry 1")).scalar_one()
    db.delete(victim); db.commit()
    recs = case_chain_records(SessionLocal(), case.id)
    res = evidence.verify_chain(recs)
    assert res["ok"] is False and res["reason"].startswith("chain link broken")


def test_signature_is_valid_under_the_published_public_key(client):
    c = _client()
    db = SessionLocal()
    case = open_case(db, c, "Signed case", actor="system")
    recs = case_chain_records(SessionLocal(), case.id)
    pub = evidence.public_key_hex()
    assert evidence.verify_chain(recs, pub_hex=pub)["ok"]
    # a different (wrong) key must fail
    other = evidence._key_id_for  # noqa: F841  (keep import path warm)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    wrong = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    assert evidence.verify_chain(recs, pub_hex=wrong)["ok"] is False


# ---------------------------------------------------------------- endpoints
def _as_client(client, email, c):
    from app.db import User
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id)); db.commit()
    from app import auth
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_staff_verify_and_proof_endpoints(admin):
    c = _client()
    db = SessionLocal()
    case = open_case(db, c, "Endpoint case", actor="system")
    r = admin.get(f"/cases/{case.id}/chain/verify")
    assert r.status_code == 200 and r.json()["ok"] is True
    p = admin.get(f"/cases/{case.id}/proof.json")
    assert p.status_code == 200
    body = p.json()
    assert body["verification"]["ok"] is True and body["entry_count"] >= 1
    assert body["public_key"] and body["scheme"] == "ed25519-sha256-v1"


def test_client_proof_seals_internal_entries(client):
    c = _client()
    db = SessionLocal()
    c.portal_enabled = True
    db2 = SessionLocal(); cc = db2.get(Client, c.id); cc.portal_enabled = True; db2.commit()
    case = open_case(db, cc, "Client proof case", actor="system")
    db = SessionLocal()
    cs = db.get(Case, case.id)
    cs.updates.append(CaseUpdate(actor="analyst", kind="note", note="internal detail", internal_only=True))
    cs.updates.append(CaseUpdate(actor="analyst", kind="note", note="client visible note", internal_only=False))
    db.commit()
    _as_client(client, "cfo@clientproof.example", cc)
    r = client.get(f"/portal/cases/{case.id}/proof.json")
    assert r.status_code == 200
    body = r.json()
    assert body["verification"]["ok"] is True
    sealed = [e for e in body["entries"] if e["sealed"]]
    revealed = [e for e in body["entries"] if not e["sealed"]]
    # internal entry is sealed (no note), visible ones carry their content
    assert any("note" not in e for e in sealed)
    assert any(e.get("note") == "client visible note" for e in revealed)
    assert all("note" not in e for e in sealed)  # sealed never leak content
