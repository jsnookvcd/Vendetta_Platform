"""The onboarding note: sent from SABINE when a person is onboarded or reactivated,
with a console link per granted module, recorded in the audit log, and never a
reason for onboarding to fail."""
import pytest

from app import notify
from app.config import settings
from app.db import AuditLog, SessionLocal, Staff


@pytest.fixture()
def outbox():
    sent = []
    notify.use_sender(lambda to, subject, body: sent.append((to, subject, body)) or "fake")
    yield sent
    notify.use_sender(None)


def _wire(admin, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "https://platform.vendettacd.io")
    admin.post("/connections/module/incident-response",
               data={"base_url": "http://incident-response:8000", "api_token": "t", "status": "in-progress",
                     "public_url": "https://ir.vendettacd.io"})
    admin.post("/connections/module/professional-services",
               data={"base_url": "http://professional-services:8000", "api_token": "t", "status": "in-progress",
                     "public_url": "https://osp.vendettacd.io"})


def test_onboarding_sends_welcome_with_granted_consoles(admin, monkeypatch, outbox):
    _wire(admin, monkeypatch)
    r = admin.post("/staff", data={"email": "dan@vendettacd.io", "name": "Dan Baker", "profile": "incident-responder"},
                   follow_redirects=False)
    assert r.status_code == 302
    assert len(outbox) == 1
    to, subject, body = outbox[0]
    assert to == "dan@vendettacd.io" and subject == "Your Vendetta console access"
    assert "Hi Dan," in body
    assert "Vendetta Platform (analyst): https://platform.vendettacd.io" in body
    assert "Incident Response (analyst): https://ir.vendettacd.io" in body
    # the incident responder profile has no Office of Special Projects grant, so no link
    assert "osp.vendettacd.io" not in body
    assert "Sign in with your Microsoft 365 account" in body
    assert body.rstrip().endswith("SABINE\nVendetta Cyber")
    assert "—" not in body
    # recorded in the audit log
    rows = SessionLocal().query(AuditLog).filter_by(action="staff.invite").all()
    assert len(rows) == 1 and "dan@vendettacd.io sent (fake)" in rows[0].detail
    assert "Incident Response" in rows[0].detail


def test_reactivation_sends_welcome_back(admin, monkeypatch, outbox):
    _wire(admin, monkeypatch)
    admin.post("/staff", data={"email": "dan@vendettacd.io", "name": "Dan", "profile": "leadership"})
    p = SessionLocal().query(Staff).filter_by(email="dan@vendettacd.io").one()
    admin.post(f"/staff/{p.id}/active", data={"active": "false"})
    admin.post(f"/staff/{p.id}/active", data={"active": "true"})
    assert [s for _, s, _ in outbox] == ["Your Vendetta console access", "Welcome back to the Vendetta consoles"]
    assert "Incident Response (read only)" in outbox[1][2]


def test_plain_persona_signs_off_plainly(admin, monkeypatch, outbox):
    monkeypatch.setattr(settings, "persona", "plain")
    admin.post("/staff", data={"email": "dan@vendettacd.io", "name": "Dan", "profile": "soc-analyst"})
    body = outbox[0][2]
    assert "SABINE\n" not in body and body.rstrip().endswith("Vendetta Cyber")


def test_no_smtp_host_logs_only_and_never_fails_onboarding(admin, caplog):
    assert not notify.configured()
    r = admin.post("/staff", data={"email": "dan@vendettacd.io", "name": "Dan", "profile": "soc-analyst"},
                   follow_redirects=False)
    assert r.status_code == 302 and "/staff/" in r.headers["location"]
    row = SessionLocal().query(AuditLog).filter_by(action="staff.invite").one()
    assert "not sent (SMTP_HOST unset; logged only)" in row.detail


def test_sender_failure_is_recorded_not_raised(admin, monkeypatch):
    def boom(to, subject, body):
        raise ConnectionError("mail host down")
    notify.use_sender(boom)
    try:
        r = admin.post("/staff", data={"email": "dan@vendettacd.io", "name": "Dan", "profile": "soc-analyst"},
                       follow_redirects=False)
    finally:
        notify.use_sender(None)
    assert r.status_code == 302
    row = SessionLocal().query(AuditLog).filter_by(action="staff.invite").one()
    assert "not sent (failed: ConnectionError" in row.detail
    assert SessionLocal().query(Staff).filter_by(email="dan@vendettacd.io").count() == 1


def test_from_address_carries_sabine_display_name(monkeypatch):
    monkeypatch.setattr(settings, "smtp_from", "sabine@vendettacd.io")
    assert notify.from_address() == "SABINE at Vendetta Cyber <sabine@vendettacd.io>"
    monkeypatch.setattr(settings, "smtp_from", "Ops <ops@vendettacd.io>")
    assert notify.from_address() == "Ops <ops@vendettacd.io>"
