"""Analyst actions through the console, the signed timeline, noise into a
suppression, and the containment hand-off to managed-services."""
import datetime as dt

from app import evidence
from app.config import settings
from app.db import Investigation, SessionLocal, Suppression, timeline, timeline_records
from helpers import finding, ingest, make_client


def _inv(now, **kw):
    make_client()
    ingest([finding(fid="a1", at=now - dt.timedelta(minutes=4), **kw)], now=now)
    return SessionLocal().query(Investigation).one()


def _kinds(inv_id):
    return [e.kind for e in timeline(SessionLocal(), inv_id)]


def test_acknowledge_verdict_note_contain_close(admin, now):
    inv = _inv(now)
    assert admin.post(f"/investigations/{inv.id}/ack", follow_redirects=False).status_code == 302
    i = SessionLocal().get(Investigation, inv.id)
    assert i.acknowledged_by == "admin" and i.acknowledged_at and i.status == "investigating"
    admin.post(f"/investigations/{inv.id}/verdict", data={"verdict": "true_positive"})
    admin.post(f"/investigations/{inv.id}/note", data={"text": "Confirmed encryption on C:\\Users"})
    admin.post(f"/investigations/{inv.id}/contain", data={"note": "isolated via S1"})
    admin.post(f"/investigations/{inv.id}/close", data={"verdict": "", "note": "rebuilt"})
    i = SessionLocal().get(Investigation, inv.id)
    assert i.verdict == "true_positive" and i.contained_at and i.closed_at and i.status == "closed"
    assert _kinds(inv.id) == ["opened", "acknowledged", "verdict", "note", "contained", "closed"]
    chain = evidence.verify_chain(timeline_records(SessionLocal(), inv.id))
    assert chain["ok"] and chain["length"] == 6
    page = admin.get(f"/investigations/{inv.id}").text
    assert "SIGNED CHAIN INTACT" in page and inv.number in page


def test_ack_is_once_and_bad_verdict_refused(admin, now):
    inv = _inv(now)
    admin.post(f"/investigations/{inv.id}/ack")
    admin.post(f"/investigations/{inv.id}/ack")
    assert _kinds(inv.id).count("acknowledged") == 1
    r = admin.post(f"/investigations/{inv.id}/verdict", data={"verdict": "maybe"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_noise_closes_false_positive_and_creates_suppression(admin, now):
    inv = _inv(now, title="Ransomware test harness on lab box")
    r = admin.post(f"/investigations/{inv.id}/noise", data={"reason": "Approved red team harness", "days": 30,
                                                            "tool": "sentinelone", "host": "ACME-WS01",
                                                            "title_contains": "test harness"},
                   follow_redirects=False)
    assert "msg=" in r.headers["location"]
    db = SessionLocal()
    i = db.get(Investigation, inv.id)
    assert i.status == "closed" and i.verdict == "false_positive"
    sup = db.query(Suppression).one()
    assert sup.client_id == i.client_id and sup.platform_client_id == "plat-acme"
    assert (sup.tool, sup.host, sup.title_contains) == ("sentinelone", "ACME-WS01", "test harness")
    assert sup.created_by == "admin" and sup.source_investigation_id == i.id
    assert 29 <= (sup.expires_at - now).days <= 30
    assert _kinds(inv.id)[-3:] == ["suppression_created", "verdict", "closed"]
    # the same pattern no longer opens anything for this client
    later = now + dt.timedelta(hours=1)
    summ = ingest([finding(fid="a2", title="Ransomware test harness on lab box", at=later)], now=later)
    assert summ["suppressed"] == 1 and summ["opened"] == 0


def test_noise_requires_reason(admin, now):
    inv = _inv(now)
    r = admin.post(f"/investigations/{inv.id}/noise", data={"reason": "", "days": 30}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().get(Investigation, inv.id).status != "closed"
    assert SessionLocal().query(Suppression).count() == 0


def test_noise_defaults_scope_to_latest_signal(fresh_db, now):
    from app import actions
    inv = _inv(now)
    db = SessionLocal()
    i = db.get(Investigation, inv.id)
    sup = actions.noise(db, i, "analyst@vendettacd.io", "known benign")
    assert (sup.tool, sup.host) == ("sentinelone", "ACME-WS01") and sup.title_contains
    assert 29 <= (sup.expires_at - now).days <= 30


def test_prepare_containment_links_managed_services_alert(admin, now, monkeypatch):
    monkeypatch.setattr(settings, "managed_services_public_url", "https://msp.vendettacyber.com/")
    inv = _inv(now)
    admin.post(f"/investigations/{inv.id}/prepare-containment", data={"action": "isolate_host", "note": "S1 isolate"})
    i = SessionLocal().get(Investigation, inv.id)
    assert i.response == "isolate_host" and i.response_prepared_by == "admin"
    entry = [e for e in timeline(SessionLocal(), inv.id) if e.kind == "containment_prepared"][0]
    assert entry.payload["link"] == "https://msp.vendettacyber.com/alerts/a1"
    assert entry.payload["alert_ref"] == "a1"
    page = admin.get(f"/investigations/{inv.id}").text
    assert "https://msp.vendettacyber.com/alerts/a1" in page
    # MDR never acted: still open, not contained
    assert i.contained_at is None and i.status == "investigating"


def test_prepare_containment_refuses_none(admin, now):
    inv = _inv(now)
    r = admin.post(f"/investigations/{inv.id}/prepare-containment", data={"action": "none"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_publish_needs_summary_then_shares(admin, now):
    inv = _inv(now)
    r = admin.post(f"/investigations/{inv.id}/publish", data={"client_summary": "", "published": "true"},
                   follow_redirects=False)
    assert "err=" in r.headers["location"] and not SessionLocal().get(Investigation, inv.id).published
    admin.post(f"/investigations/{inv.id}/publish",
               data={"client_summary": "We isolated the host and restored from backup.", "published": "true"})
    assert SessionLocal().get(Investigation, inv.id).published
    assert "published" in _kinds(inv.id)


def test_staff_pages_render(admin, now):
    inv = _inv(now)
    for path in ("/", "/investigations", "/investigations?status=all", f"/investigations/{inv.id}", "/rules",
                 "/rules/ransomware-behavior", "/suppressions", "/coverage", "/clients",
                 f"/clients/{inv.client_id}", "/settings", "/settings/sso"):
        r = admin.get(path)
        assert r.status_code == 200, path


def test_evidence_export_verifies(admin, now, tmp_path):
    from app.evidence_export import verify_package
    inv = _inv(now)
    admin.post(f"/investigations/{inv.id}/note", data={"text": "internal note"})
    r = admin.get(f"/investigations/{inv.id}/evidence/export.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    p = tmp_path / "x.zip"
    p.write_bytes(r.content)
    report = verify_package(str(p))
    assert report["ok"] is True and report["subject"]["name"] == inv.number
