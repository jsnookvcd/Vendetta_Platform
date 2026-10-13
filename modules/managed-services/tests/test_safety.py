"""The action safety gate: read-only mode disables every tool write, destructive
actions need confirmation, and both are logged as blocked without calling the tool."""
from app import actions as act
from app import connectors
from app.config import settings
from app.db import ActionLog, SessionLocal

from test_app import FakeS1, _client_with_s1

_WRITES = {"mitigate", "incident", "disconnect", "reconnect"}


def _wrote(fake):
    return any(c[0] in _WRITES for c in fake.calls)


def _synced_alert():
    fake = FakeS1()
    db, c = _client_with_s1(fake)
    from app.sync import sync_client_tool
    sync_client_tool(db, c, "sentinelone")
    from app.db import Alert
    return fake, SessionLocal().query(Alert).one()


def test_readonly_blocks_every_tool_action_and_does_not_call_tool(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", True)
    fake, a = _synced_alert()
    # a non-destructive source action is still blocked in read-only mode
    r = admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_resolve_fp"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and "read-only" in r.headers["location"]
    # a destructive one too
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"})
    assert not _wrote(fake)  # the connector was never touched for a write
    rows = SessionLocal().query(ActionLog).filter_by(alert_id=a.id).all()
    assert rows and all(x.result == "blocked" for x in rows)


def test_readonly_banner_shows(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", True)
    assert "Read-only mode" in admin.get("/").text


def test_destructive_action_needs_confirm(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    # without confirm: refused, tool not called
    r = admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert not _wrote(fake)
    assert SessionLocal().query(ActionLog).filter_by(alert_id=a.id).one().result == "blocked"
    # with confirm: it runs
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"})
    assert ("mitigate", "quarantine", ["t9"]) in fake.calls


def test_nondestructive_action_runs_without_confirm(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_resolve_fp"})
    assert ("incident", "resolved", "false_positive") in fake.calls


def test_device_isolate_needs_confirm(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    dev_id = a.device_id
    r = admin.post(f"/devices/{dev_id}/action", data={"action_id": "s1_disconnect"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and not _wrote(fake)
    admin.post(f"/devices/{dev_id}/action", data={"action_id": "s1_disconnect", "confirm": "true"})
    assert ("disconnect", ["a1"]) in fake.calls


def test_settings_shows_actions_mode(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", True)
    assert "read-only (tool writes disabled)" in admin.get("/settings").text
