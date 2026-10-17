"""Signal pull from managed-services (mocked transport) and the persisted detection
run: numbering, attach vs open, suppression hits, overrides from the database."""
import datetime as dt

import pytest
from sqlalchemy import select

from app import detect
from app.config import settings
from app.db import Investigation, InvestigationSignal, RuleOverride, SessionLocal, Signal, Suppression, timeline
from helpers import bearer, finding, ingest, make_client, ms_transport, route


@pytest.fixture()
def ms(monkeypatch):
    monkeypatch.setattr(settings, "managed_services_url", "http://managed-services:8000")
    monkeypatch.setattr(settings, "managed_services_token", "mstok")


def test_pull_reads_all_findings_with_bearer(fresh_db, ms):
    make_client()
    captured = {}
    rows = [finding(), finding(pid="plat-unknown", client="Nobody")]
    summ = detect.run(SessionLocal(), transport=ms_transport(rows, captured))
    assert captured["path"] == "/api/findings" and captured["params"] == {"status": "all"}
    assert captured["auth"] == "Bearer mstok"
    assert summ["signals"] == 2 and summ["unmapped"] == 1 and summ["opened"] == 1
    db = SessionLocal()
    s = db.get(Signal, rows[0]["id"])
    assert s.tool == "sentinelone" and s.host == "ACME-WS01" and s.client_id is not None
    assert db.get(Signal, rows[1]["id"]).client_id is None
    st = detect.state()
    assert st["configured"] and st["token_set"] and st["last_ok"] is True


def test_pull_failure_is_recorded(fresh_db, ms):
    with pytest.raises(detect.DetectError):
        detect.run(SessionLocal(), transport=ms_transport([], status=401))
    assert detect.state()["last_ok"] is False and "rejected" in detect.state()["last_detail"]


def test_api_detect_run(client, ms, monkeypatch):
    make_client()
    route(monkeypatch, detect, ms_transport([finding()]))
    r = client.post("/api/detect/run", headers=bearer())
    assert r.status_code == 200 and r.json()["ok"] and r.json()["opened"] == 1
    assert r.json()["investigations"][0].startswith(f"MDR-{dt.datetime.now(dt.timezone.utc).year}-")
    assert client.post("/api/detect/run").status_code == 401


def test_api_detect_run_409_unconfigured(client):
    assert client.post("/api/detect/run", headers=bearer()).status_code == 409


def test_scheduler_idles_without_source_or_interval(monkeypatch):
    import threading
    started = []
    monkeypatch.setattr(threading.Thread, "start", lambda self: started.append(self.name))
    monkeypatch.setattr(settings, "managed_services_url", "")
    monkeypatch.setattr(settings, "detect_interval_seconds", 120)
    detect.start_scheduler(SessionLocal)
    monkeypatch.setattr(settings, "managed_services_url", "http://managed-services:8000")
    monkeypatch.setattr(settings, "detect_interval_seconds", 0)
    detect.start_scheduler(SessionLocal)
    assert started == []
    monkeypatch.setattr(settings, "detect_interval_seconds", 120)
    detect.start_scheduler(SessionLocal)
    assert started == ["mdr-detect"]


def test_api_calls_are_attributed_to_the_named_actor(client):
    from app.db import AuditLog
    make_client()
    r = client.post("/api/suppressions", json={"platform_client_id": "plat-acme", "tool": "aws",
                                               "reason": "pattern rejected 3 times", "days": 7},
                    headers=bearer("sabine"))
    assert r.status_code == 200
    db = SessionLocal()
    row = db.query(AuditLog).filter_by(action="suppression.add").one()
    assert row.actor == "api:sabine"
    assert db.get(Suppression, r.json()["id"]).created_by == "api:sabine"


def test_open_then_attach_and_numbering(fresh_db, now):
    make_client()
    ingest([finding(fid="a1", at=now - dt.timedelta(minutes=3))], now=now)
    db = SessionLocal()
    invs = db.execute(select(Investigation)).scalars().all()
    assert len(invs) == 1
    inv = invs[0]
    assert inv.number == f"MDR-{now.year}-0001" and inv.rule_key == "ransomware-behavior"
    assert inv.severity == "critical" and inv.mitre == ["T1486"] and inv.response == "isolate_host"
    assert inv.first_signal_at == now - dt.timedelta(minutes=3) and inv.opened_at == now
    # the same rule, client and host again: attaches, does not open
    later = now + dt.timedelta(minutes=5)
    summ = ingest([finding(fid="a2", title="Ransomware note dropped", at=later)], now=later)
    assert summ["opened"] == 0 and summ["attached"] == 1
    db = SessionLocal()
    assert db.query(Investigation).count() == 1
    assert {link.signal_id for link in db.get(Investigation, inv.id).links} == {"a1", "a2"}
    kinds = [e.kind for e in timeline(db, inv.id)]
    assert kinds == ["opened", "signals_attached"]
    # another host: a second investigation with the next number
    ingest([finding(fid="b1", host="ACME-WS02", at=later)], now=later)
    numbers = sorted(i.number for i in SessionLocal().query(Investigation).all())
    assert numbers == [f"MDR-{now.year}-0001", f"MDR-{now.year}-0002"]


def test_rerun_is_idempotent(fresh_db, now):
    make_client()
    ingest([finding(fid="a1", at=now)], now=now)
    summ = ingest([finding(fid="a1", at=now)], now=now + dt.timedelta(minutes=1))
    assert summ["opened"] == 0 and summ["attached"] == 0
    assert SessionLocal().query(InvestigationSignal).count() == 1


def test_closed_investigation_does_not_reopen_from_old_signals_but_new_ones_open(fresh_db, now):
    make_client()
    ingest([finding(fid="a1", at=now)], now=now)
    db = SessionLocal()
    inv = db.query(Investigation).one()
    inv.status = "closed"
    db.commit()
    assert ingest([], now=now + dt.timedelta(minutes=2))["opened"] == 0
    summ = ingest([finding(fid="a2", at=now + dt.timedelta(minutes=3))], now=now + dt.timedelta(minutes=3))
    assert summ["opened"] == 1


def test_correlation_rule_from_db(fresh_db, now):
    make_client()
    rows = [finding(fid=f"f{i}", tool="entra", kind="incident", severity="medium", title="Failed sign-in for user",
                    host=f"user{i}@acme.example", at=now - dt.timedelta(minutes=i)) for i in range(4)]
    assert ingest(rows, now=now)["opened"] == 0  # four is under the threshold of five
    rows.append(finding(fid="f9", tool="entra", kind="incident", severity="medium", title="Failed sign-in for user",
                        host="admin@acme.example", at=now))
    ingest(rows, now=now)
    inv = SessionLocal().query(Investigation).filter_by(rule_key="password-spray").one()
    assert len(inv.links) == 5 and inv.title == "Failed sign-in burst at Acme Corp" and inv.group_key == ""


def test_suppression_counts_hits_once(fresh_db, now):
    c = make_client()
    db = SessionLocal()
    sup = Suppression(client_id=c.id, platform_client_id="plat-acme", tool="sentinelone", reason="lab",
                      expires_at=now + dt.timedelta(days=5), created_by="t")
    db.add(sup)
    db.commit()
    summ = ingest([finding(fid="a1", at=now)], now=now)
    assert summ["suppressed"] == 1 and summ["opened"] == 0
    ingest([], now=now + dt.timedelta(minutes=1))
    db = SessionLocal()
    assert db.get(Suppression, sup.id).hits == 1
    assert db.get(Signal, "a1").suppression_id == sup.id


def test_override_from_db_disables_and_rerates(fresh_db, now):
    a = make_client()
    b = make_client(name="Bravo", pid="plat-bravo", domains="bravo.example")
    db = SessionLocal()
    db.add(RuleOverride(rule_key="ransomware-behavior", client_id=a.id, disabled=True, updated_by="t"))
    db.add(RuleOverride(rule_key="ransomware-behavior", client_id=b.id, severity="high", updated_by="t"))
    db.commit()
    ingest([finding(fid="a1", at=now), finding(fid="b1", pid="plat-bravo", client="Bravo", at=now)], now=now)
    invs = SessionLocal().query(Investigation).filter_by(rule_key="ransomware-behavior").all()
    assert [(i.platform_client_id, i.severity) for i in invs] == [("plat-bravo", "high")]
