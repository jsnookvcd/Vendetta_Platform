"""Response-action RBAC: only can_act users may run actions, and a destructive
action needs an authorized approver, recorded in the signed action chain."""
from app import auth, connectors
from app.config import settings
from app.db import SessionLocal, User

from test_app import FakeS1, _actions, _client_with_s1
from test_safety import _wrote


def _synced_alert():
    fake = FakeS1()
    db, c = _client_with_s1(fake)
    from app.sync import sync_client_tool
    sync_client_tool(db, c, "sentinelone")
    from app.db import Alert
    return fake, SessionLocal().query(Alert).one()


def _as(client, email, role="analyst", can_act=True, can_approve=False):
    db = SessionLocal()
    u = db.query(User).filter_by(email=email).one_or_none()
    if not u:
        u = User(email=email, role=role); db.add(u)
    u.role, u.can_act, u.can_approve = role, can_act, can_approve
    db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_user_without_can_act_is_refused(client, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    _as(client, "viewer@vendettacd.io", can_act=False)
    r = client.post(f"/alerts/{a.id}/action", data={"action_id": "s1_resolve_fp"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and "permission" in r.headers["location"]
    assert not _wrote(fake)


def test_destructive_blocked_without_approver(client, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    _as(client, "analyst@vendettacd.io", can_act=True, can_approve=False)  # cannot self-approve
    client.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"})
    assert not _wrote(fake)
    assert _actions(a.id).one().result == "blocked"


def test_destructive_runs_with_named_approver_and_records_it(client, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    _as(client, "lead@vendettacd.io", role="analyst", can_act=False, can_approve=True)  # an approver exists
    _as(client, "analyst@vendettacd.io", can_act=True, can_approve=False)  # acting user
    client.post(f"/alerts/{a.id}/action",
                data={"action_id": "s1_quarantine", "confirm": "true", "approver": "lead@vendettacd.io"})
    assert ("mitigate", "quarantine", ["t9"]) in fake.calls
    row = _actions(a.id, result="ok").one()
    assert row.approver == "lead@vendettacd.io"
    # the approver is inside the signed chain
    from app import evidence
    from app.db import client_chain_records
    recs = client_chain_records(SessionLocal(), a.client_id)
    assert evidence.verify_chain(recs)["ok"]
    assert any(r["fields"].get("approver") == "lead@vendettacd.io" for r in recs)


def test_admin_self_approves_by_default(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    fake, a = _synced_alert()
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"})
    assert ("mitigate", "quarantine", ["t9"]) in fake.calls
    assert _actions(a.id, result="ok").one().approver == "admin"


def test_strict_mode_forbids_self_approval(admin, monkeypatch):
    monkeypatch.setattr(settings, "actions_readonly", False)
    monkeypatch.setattr(settings, "require_second_approver", True)
    fake, a = _synced_alert()
    # admin naming themselves is rejected; the action is blocked
    admin.post(f"/alerts/{a.id}/action",
               data={"action_id": "s1_quarantine", "confirm": "true", "approver": "admin"})
    assert not _wrote(fake)
    assert _actions(a.id).one().result == "blocked"


def test_team_caps_requires_admin(client):
    db = SessionLocal()
    u = User(email="analyst@vendettacd.io", role="analyst"); db.add(u); db.commit()
    _as(client, "analyst@vendettacd.io", can_act=True)
    r = client.post(f"/team/{u.id}/caps", data={"can_act": "true", "can_approve": "true"},
                    follow_redirects=False)
    assert r.status_code == 403
