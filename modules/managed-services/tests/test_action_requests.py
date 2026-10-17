"""Requested response actions for the Slack responder: look a host up, ask to
contain it, a different person approves, and only then does CrowdStrike get the
call. Read-only mode, rights and expiry all hold."""
import datetime as dt

import pytest

from app import actions as act, connectors
from app.config import settings
from app.db import ActionLog, ActionRequest, Alert, Client, Device, SessionLocal, User

BRIDGE = "ms-bridge"


class FakeFalcon:
    configured = True

    def __init__(self):
        self.calls = []

    def contain(self, ref, ids):
        self.calls.append(("contain", ref, ids))

    def lift_containment(self, ref, ids):
        self.calls.append(("lift", ref, ids))


@pytest.fixture()
def world(client, monkeypatch):
    monkeypatch.setattr(settings, "bridge_token", BRIDGE)
    monkeypatch.setattr(settings, "actions_readonly", False)
    falcon = FakeFalcon()
    real_get = connectors.get
    monkeypatch.setattr(connectors, "get", lambda tool: falcon if tool == "crowdstrike" else real_get(tool))
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", platform_client_id="plat-rb", crowdstrike_cid="cid-rb")
    other = Client(name="Harbor Point", platform_client_id="plat-hp")
    db.add_all([c, other])
    db.flush()
    d = Device(client_id=c.id, tool="crowdstrike", external_id="aid-ws01", hostname="RB-WS01", status="online",
               last_seen=dt.datetime.now(dt.timezone.utc))
    d2 = Device(client_id=other.id, tool="crowdstrike", external_id="aid-hp", hostname="HP-WS01")
    db.add_all([d, d2])
    db.flush()
    db.add(Alert(client_id=c.id, device_id=d.id, tool="crowdstrike", external_id="det1", severity="critical",
                 title="Ransomware behavior: vssadmin delete shadows"))
    db.add_all([User(email="dan@vendettacd.io", role="analyst", source="platform", can_act=True, can_approve=False),
                User(email="kenedi@vendettacd.io", role="analyst", source="platform", can_act=True, can_approve=True),
                User(email="jordan@vendettacd.io", role="admin", source="platform"),
                User(email="vic@vendettacd.io", role="viewer", source="platform")])
    db.commit()
    return {"client": client, "falcon": falcon, "device": d.id, "other_device": d2.id}


def _h(person):
    return {"Authorization": f"Bearer {BRIDGE}", "X-Vendetta-Actor": "slack", "X-Vendetta-On-Behalf-Of": person}


def _ask(w, person="dan@vendettacd.io", action="cs_contain", device=None, pid="plat-rb"):
    return w["client"].post("/api/action-requests", headers=_h(person), json={
        "platform_client_id": pid, "device_id": device or w["device"], "action_id": action,
        "reason": "ransomware beacon", "source_ref": "VCD-IR-2026-781"})


def test_device_lookup(world):
    r = world["client"].get("/api/devices?platform_client_id=plat-rb&q=ws01", headers=_h("vic@vendettacd.io"))
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["actions_readonly"] is False and len(d["devices"]) == 1
    dev = d["devices"][0]
    assert dev["hostname"] == "RB-WS01" and dev["open_alerts"][0]["severity"] == "critical"
    assert {a["id"]: a["destructive"] for a in dev["actions"]} == {"cs_contain": True, "cs_lift": False}


def test_contain_needs_a_second_person(world):
    r = _ask(world)
    assert r.status_code == 200, r.text
    req = r.json()
    assert req["status"] == "pending" and req["destructive"] and not world["falcon"].calls
    # the requester cannot approve their own
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("dan@vendettacd.io"), json={"approve": True})
    assert r.status_code == 403 and not world["falcon"].calls
    # someone without approval rights cannot either
    db = SessionLocal()
    db.add(User(email="sam@vendettacd.io", role="analyst", source="platform", can_act=True, can_approve=False))
    db.commit()
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("sam@vendettacd.io"), json={"approve": True})
    assert r.status_code == 403
    # an approver can
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("kenedi@vendettacd.io"), json={"approve": True})
    assert r.status_code == 200 and r.json()["status"] == "done"
    assert world["falcon"].calls == [("contain", "cid-rb", ["aid-ws01"])]
    log = SessionLocal().query(ActionLog).filter_by(action="Network contain").one()
    assert log.actor == "dan@vendettacd.io via slack" and log.approver == "kenedi@vendettacd.io" and log.result == "ok"
    assert log.content_hash  # on the signed action chain
    # deciding twice is refused with the current state
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("jordan@vendettacd.io"), json={"approve": True})
    assert r.status_code == 409 and r.json()["status"] == "done"
    assert len(world["falcon"].calls) == 1


def test_admin_requester_still_needs_someone_else(world, monkeypatch):
    monkeypatch.setattr(settings, "require_second_approver", False)
    req = _ask(world, person="jordan@vendettacd.io").json()
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("jordan@vendettacd.io"), json={"approve": True})
    assert r.status_code == 403 and not world["falcon"].calls


def test_reject_and_expiry(world):
    req = _ask(world).json()
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("kenedi@vendettacd.io"),
                             json={"approve": False, "note": "wrong host"})
    assert r.json()["status"] == "rejected" and not world["falcon"].calls
    req = _ask(world).json()
    db = SessionLocal()
    row = db.get(ActionRequest, req["id"])
    row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("kenedi@vendettacd.io"), json={"approve": True})
    assert r.status_code == 409 and r.json()["status"] == "expired" and not world["falcon"].calls


def test_lift_runs_at_once(world):
    r = _ask(world, action="cs_lift").json()
    assert r["status"] == "done" and world["falcon"].calls == [("lift", "cid-rb", ["aid-ws01"])]


def test_refusals(world, monkeypatch):
    assert _ask(world, person="vic@vendettacd.io").status_code == 403          # viewer
    assert _ask(world, device=world["other_device"]).status_code == 404        # another client's host
    assert _ask(world, action="s1_disconnect").status_code == 400              # wrong tool
    db = SessionLocal()
    u = db.query(User).filter_by(email="dan@vendettacd.io").one()
    u.can_act = False
    db.commit()
    assert _ask(world).status_code == 403                                      # no right to act
    monkeypatch.setattr(settings, "actions_readonly", True)
    r = _ask(world, person="kenedi@vendettacd.io")
    assert r.status_code == 409 and "read-only" in r.json()["detail"]
    assert not world["falcon"].calls


def test_requester_losing_rights_while_waiting_blocks_execution(world):
    req = _ask(world).json()
    db = SessionLocal()
    db.query(User).filter_by(email="dan@vendettacd.io").one().can_act = False
    db.commit()
    r = world["client"].post(f"/api/action-requests/{req['id']}/decide", headers=_h("kenedi@vendettacd.io"), json={"approve": True})
    assert r.json()["status"] == "blocked" and not world["falcon"].calls


def test_bridge_header_needs_the_bridge_token(world):
    from app import auth
    r = world["client"].post("/api/action-requests", headers={"Authorization": f"Bearer {auth.api_token()}",
                                                              "X-Vendetta-On-Behalf-Of": "kenedi@vendettacd.io"},
                             json={"platform_client_id": "plat-rb", "device_id": world["device"], "action_id": "cs_contain"})
    # the module token is its own actor ("api"), which holds no rights to act
    assert r.status_code == 403 and not world["falcon"].calls
    assert act.spec("cs_contain").danger
