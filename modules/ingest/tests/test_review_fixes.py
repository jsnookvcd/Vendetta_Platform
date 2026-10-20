"""Regression tests for the independent security review of Telemetry Ingest. Each
test names the finding it pins; together they keep the module's two promises: one
client never affects another, and every stored event stays provable."""
import datetime as dt
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import insert, select

from app import auth, pipeline, receipts, sigma, stream, worker
from app.config import settings
from app.db import Anchor, Batch, Connector, Detection, Event, Rejected, SessionLocal
from helpers import as_user, bearer, make_client, make_connector, push, signed, signin


def _ingest(conn, records):
    db = SessionLocal()
    try:
        return pipeline.ingest_records(db, db.get(Connector, conn.id), records)
    finally:
        db.close()


def _run():
    db = SessionLocal()
    try:
        return stream.run(db)
    finally:
        db.close()


# ---------------------------------------------------------------- high
def test_h1_distinct_threshold_counts_only_this_tenant(fresh_db):
    a = make_connector(make_client())
    b = make_connector(make_client(name="Beta", pid="plat-beta", domains="beta.example"))
    _ingest(a, [signin(i, user=f"u{i}@acme.example", ip="203.0.113.9", ok=False,
                       at=f"2026-10-19T12:00:{i:02d}Z") for i in range(9)])
    _ingest(b, [signin(50, user="x@beta.example", ip="198.51.100.7", ok=False, at="2026-10-19T12:00:30Z")])
    _run()
    assert SessionLocal().execute(select(Detection).where(Detection.kind == "sigma")).first() is None


def test_h2_an_event_committed_late_with_a_lower_seq_is_still_evaluated(fresh_db):
    conn = make_connector(make_client(), source="entra_audit")
    from test_stream import _audit_role
    _ingest(conn, [_audit_role(1, role="Reports Reader")])
    _run()
    db = SessionLocal()
    first = db.execute(select(Event)).scalar_one()
    # A row whose transaction was still open during the pass: lower seq, unevaluated.
    late = _audit_role(2)
    _ingest(conn, [late])
    row = db.execute(select(Event).where(Event.dedupe_key == "aud-2")).scalar_one()
    db.execute(Event.__table__.update().where(Event.seq == row.seq).values(seq=first.seq - 100))
    db.commit()
    db.close()
    _run()
    assert SessionLocal().execute(select(Detection).where(Detection.kind == "sigma")).scalar_one()
    assert SessionLocal().execute(select(Event).where(Event.detected.is_(False))).first() is None


def test_h3_one_bad_record_never_fails_the_delivery(client):
    conn = make_connector(make_client())
    records = [signin(1, userPrincipalName="nul\x00user@acme.example"),
               signin(2, status={"errorCode": float("nan")}),
               signin(3, appDisplayName="lone \ud800 surrogate"),
               signin(4)]
    db = SessionLocal()
    out = pipeline.ingest_records(db, db.get(Connector, conn.id), records)
    db.close()
    assert out["stored"] == 2 and out["rejected"] == 2
    nul = SessionLocal().execute(select(Event).where(Event.dedupe_key == "si-1")).scalar_one()
    assert "\ufffd" in nul.user and receipts.verify_proof is not None
    reasons = [r.reason for r in SessionLocal().execute(select(Rejected)).scalars()]
    assert any("NaN" in r for r in reasons) and any("surrogate" in r for r in reasons)


def test_h3_a_large_delivery_is_stored_in_chunks(client, monkeypatch):
    conn = make_connector(make_client())
    monkeypatch.setattr(settings, "max_push_records", 5000)
    r = push(client, conn, [signin(i) for i in range(4000)])
    assert r.status_code == 202 and r.json()["stored"] == 4000


def test_h3_a_poisoned_page_does_not_stick_a_pull_connector(fresh_db):
    import httpx
    from app import connectors
    c = make_client()
    conn = make_connector(c, source="entra_signins", config={"tenant_id": "contoso.onmicrosoft.com",
                                                             "client_id": "app"},
                          credentials=json.dumps({"client_secret": "s"}))

    def handler(req):
        if "oauth2" in req.url.path:
            return httpx.Response(200, json={"access_token": "t"})
        page = {"value": [signin(1, userPrincipalName="a\x00b"), signin(2),
                          signin(3, status={"errorCode": float("inf")})]}
        return httpx.Response(200, content=json.dumps(page).encode(),  # Python writes Infinity
                              headers={"Content-Type": "application/json"})
    db = SessionLocal()
    res = connectors.run(db, db.get(Connector, conn.id), transport=httpx.MockTransport(handler))
    assert res["ok"] and res["stored"] == 2 and res["rejected"] == 1
    assert SessionLocal().get(Connector, conn.id).cursor.get("since")


def test_h4_future_dated_records_cannot_crowd_out_other_tenants(client):
    a = make_connector(make_client(), source="entra_audit")
    b = make_connector(make_client(name="Beta", pid="plat-beta", domains="beta.example"), source="entra_audit")
    from test_stream import _audit_role
    _ingest(a, [_audit_role(i, at="2099-01-01T00:00:00Z") for i in range(3)])
    _ingest(b, [_audit_role(9)])
    _run()
    ev = SessionLocal().execute(select(Event).where(Event.tenant == "plat-acme")).scalars().first()
    assert ev.time <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=6)
    assert json.loads(ev.event_text)["time_dt"].startswith("2099")  # the vendor's time is kept in the event
    rows = client.get("/api/findings?status=all&limit=1", headers=bearer()).json()
    assert rows[0]["subject"]["platform_client_id"] == "plat-beta"  # most recently updated first
    newer = client.get("/api/findings", params={"status": "all", "updated_since": rows[0]["updated_at"]},
                       headers=bearer())
    assert newer.status_code == 200 and newer.json() == []


# ---------------------------------------------------------------- medium
@pytest.mark.parametrize("number", [1e16, -0.0, 1.5e300, 8.0, 0.1, 5e-324])
def test_m5_numbers_survive_storage_and_still_verify(fresh_db, number):
    conn = make_connector(make_client())
    _ingest(conn, [signin(1, location={"countryOrRegion": "US", "geoCoordinates": {"latitude": number,
                                                                                    "longitude": 2.5}})])
    db = SessionLocal()
    pipeline.seal(db)
    ev = db.execute(select(Event)).scalar_one()
    proof = json.loads(json.dumps(pipeline.proof(db, ev)))  # through JSON, as a client receives it
    assert receipts.verify_proof(proof, json.loads(ev.raw))["ok"]


def test_m6_unpinned_forgery_is_caught_once_the_key_is_pinned(fresh_db):
    conn = make_connector(make_client())
    _ingest(conn, [signin(1)])
    db = SessionLocal()
    pipeline.seal(db)
    ev = db.execute(select(Event)).scalar_one()
    proof = pipeline.proof(db, ev)
    from app import evidence
    forger = Ed25519PrivateKey.generate()
    fpub = forger.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    forged = json.loads(json.dumps(proof))
    forged["event"]["message"] = "fabricated"
    forged["receipt"]["event_sha256"] = receipts.event_hash(forged["event"])
    leaf = receipts.leaf_hash(forged["receipt"]["raw_sha256"], forged["receipt"]["event_sha256"])
    forged["receipt"]["audit_path"] = []
    hdr = dict(forged["batch"]["header"], size=1, root=leaf.hex(), key_id=receipts.key_id_for(fpub))
    bh = receipts.header_hash(hdr)
    forged["batch"].update(header=hdr, batch_hash=bh, signature=forger.sign(bytes.fromhex(bh)).hex(), public_key=fpub)
    forged["receipt"]["leaf_index"] = 0
    assert receipts.verify_proof(forged)["ok"] is True and receipts.verify_proof(forged)["pinned"] is False
    pinned = receipts.verify_proof(forged, public_key_hex=evidence.public_key_hex())
    assert pinned["ok"] is False and pinned["reason"] == "the batch was signed by a different key"


def test_m6_chain_checks_key_consistency_emptiness_and_the_anchor(fresh_db, monkeypatch):
    conn = make_connector(make_client())
    other = make_connector(make_client(name="Beta", pid="plat-beta", domains="beta.example"))
    monkeypatch.setattr(settings, "seal_max_events", 1)
    _ingest(conn, [signin(1), signin(2), signin(3)])
    _ingest(other, [signin(1)])
    db = SessionLocal()
    pipeline.seal(db)
    worker.anchor(db)
    chain = pipeline.chain(db, "plat-acme", 1, 100)
    anchor = pipeline.latest_anchor(db, "plat-acme")
    from app import evidence
    key = evidence.public_key_hex()
    assert receipts.verify_chain(chain, key, anchor)["anchored"] is True
    assert receipts.verify_chain([], key)["reason"] == "the chain is empty"
    cut = receipts.verify_chain(chain[:2], key, anchor)
    assert cut["ok"] is False and "batches were removed" in cut["reason"]
    # The client's anchor statement names only its own tenant.
    assert set(anchor["document"]["tenants"]) == {"plat-acme"}
    assert "plat-beta" not in json.dumps(anchor)
    glob = db.execute(select(Anchor)).scalar_one()
    assert anchor["document"]["anchor_digest"] == glob.digest


def test_m7_duplicate_keys_and_non_finite_numbers_are_refused_at_the_door(client):
    conn = make_connector(make_client())
    for body in (b'[{"id":"si-1","userPrincipalName":"mallory","userPrincipalName":"alice"}]',
                 b'[{"id":"si-1","n":NaN}]', b'[{"id":"si-1","n":Infinity}]', b"[" * 100000 + b"]" * 100000):
        r = client.post(f"/api/ingest/{conn.id}", content=body, headers=signed(body, "push-secret-123"))
        assert r.status_code == 400, body[:40]


def test_m8_rules_run_in_bounded_time_on_hostile_values():
    rec = sigma.compile(open("app/rules/endpoint_recovery_inhibition.yml").read())
    glob = sigma.compile("title: g\nlogsource: {category: process_creation}\ndetection:\n  s:\n"
                         "    process.cmd_line: '*a*b*c*d*e*f*'\n  condition: s\nlevel: low\n")
    ev = {"class_uid": 1007, "activity_id": 1, "time": 1, "severity_id": 1,
          "metadata": {"product": {"name": "x"}, "log_name": "crowdstrike_fdr"},
          "process": {"cmd_line": "bcdedit " * 30000}}
    t = time.monotonic()
    rec.matches(ev)
    ev["process"]["cmd_line"] = "a" * 250000
    glob.matches(ev)
    assert time.monotonic() - t < 1.0
    ev["process"]["cmd_line"] = "xx a yy b c d e zz f"
    assert glob.matches(ev) is True


def test_m9_read_token_reads_and_cannot_act_and_viewers_never_see_tokens(client):
    make_connector(make_client())
    read = {"Authorization": f"Bearer {auth.api_read_token()}"}
    assert client.get("/api/findings", headers=read).status_code == 200
    assert client.get("/api/module", headers=read).status_code == 200
    for path in ("/api/seal", "/api/stream/run", "/api/provision/sync"):
        assert client.post(path, headers=read).status_code == 401, path
    as_user(client, "v@vendettacd.io", role="viewer")
    page = client.get("/settings").text
    assert auth.api_token() not in page and auth.api_read_token() not in page
    as_user(client, "ad@vendettacd.io", role="admin")
    assert auth.api_token() in client.get("/settings").text


def test_m10_bucket_routes_cannot_overlap_and_collisions_are_dropped(admin):
    a = make_client()
    b = make_client(name="Beta", pid="plat-beta", domains="beta.example")
    form = {"source": "cloudtrail", "config.bucket": "org-trail", "config.prefix": "AWSLogs/o-abc/"}
    r1 = admin.post("/connectors", data={**form, "client_id": a.id}, follow_redirects=False)
    assert "err=" not in r1.headers["location"]
    for prefix in ("AWSLogs/o-abc/", "AWSLogs/", "AWSLogs/o-abc/111/"):
        r = admin.post("/connectors", data={**form, "client_id": b.id, "config.prefix": prefix},
                       follow_redirects=False)
        assert "overlaps" in r.headers["location"], prefix
    r = admin.post("/connectors", data={**form, "client_id": b.id, "config.prefix": ""}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    # Two connectors written straight to the database with the same route: both dropped.
    make_connector(b, source="cloudtrail", config={"bucket": "org-trail", "prefix": "AWSLogs/o-abc/"})
    assert worker.bucket_routes(SessionLocal()) == {}


def test_m10_cloudtrail_connector_bound_to_an_account_refuses_others(fresh_db):
    conn = make_connector(make_client(), source="cloudtrail", config={"account_id": "111111111111"})
    base = {"eventVersion": "1.08", "eventTime": "2026-10-19T12:00:00Z", "eventSource": "iam.amazonaws.com",
            "eventName": "ListUsers", "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.5",
            "userIdentity": {"type": "IAMUser", "userName": "bob"}}
    out = _ingest(conn, [dict(base, eventID="e1", recipientAccountId="111111111111"),
                         dict(base, eventID="e2", recipientAccountId="222222222222")])
    assert out["stored"] == 1 and out["rejected"] == 1


def test_m11_chain_export_never_loads_leaves(fresh_db):
    conn = make_connector(make_client())
    _ingest(conn, [signin(1)])
    db = SessionLocal()
    pipeline.seal(db)
    db.close()
    db = SessionLocal()
    pipeline.chain(db, "plat-acme")
    b = db.execute(select(Batch)).scalar_one()
    assert "leaves" not in b.__dict__


# ---------------------------------------------------------------- low
def test_l12_blank_tenant_is_refused(client):
    assert client.get("/api/events?platform_client_id=", headers=bearer()).status_code == 422


def test_l14_size_and_bad_headers_reveal_nothing(client):
    conn = make_connector(make_client())
    big = {"Content-Length": str(settings.max_push_bytes + 1), "Content-Type": "application/json"}
    known = client.post(f"/api/ingest/{conn.id}", content=b"[]", headers=big)
    unknown = client.post("/api/ingest/" + "0" * 32, content=b"[]", headers=big)
    assert known.status_code == unknown.status_code
    odd = {"Authorization": "Bearer caf\u00e9".encode("utf-8")}
    assert client.post(f"/api/ingest/{conn.id}", json=[], headers=odd).status_code == 404
    assert client.get("/api/findings", headers=odd).status_code == 401


def test_l16_new_push_secret_is_shown_once_and_never_in_a_cookie(admin):
    c = make_client()
    r = admin.post("/connectors", data={"client_id": c.id, "source": "entra_signins"}, follow_redirects=False)
    assert "session" not in r.headers.get("set-cookie", "")
    conn = SessionLocal().execute(select(Connector)).scalar_one()
    page = admin.get(r.headers["location"]).text
    assert conn.webhook_secret in page
    assert conn.webhook_secret not in admin.get(r.headers["location"]).text


def test_executive_portal_view_gets_no_downloads(client):
    c = make_client(execs="ceo@acme.example")
    as_user(client, "ceo@acme.example", role="client", client_id=c.id)
    assert client.get("/portal").status_code == 200
    assert client.get("/portal/chain.json").status_code == 404


def test_chain_export_is_rate_limited(client):
    c = make_client()
    as_user(client, "it@acme.example", role="client", client_id=c.id)
    from app import main
    main._EXPORT_HITS.clear()
    assert client.get("/portal/chain.json").status_code == 200
    assert client.get("/portal/chain.json").status_code == 429
