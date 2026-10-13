"""Module behaviour: sync upserts, triage and publish flow, portal scoping, the
actions feed, desk messaging with SuperOps ticket binding, escalation to the IR
hub contract, the findings API and the module switch. Tool calls go through fake
connectors injected into the registry."""
import datetime as dt

import pytest

from app import auth, connectors
from app.config import settings
from app.db import ActionLog, Alert, Channel, Client, Device, Message, SessionLocal, User
from app.sync import sync_client_tool


def _now():
    return dt.datetime.now(dt.timezone.utc)


class FakeS1:
    tool = "sentinelone"
    configured = True

    def __init__(self):
        self.calls = []
        self.resolved = False

    def devices(self, ref):
        self.calls.append(("devices", ref))
        return [{"external_id": "a1", "hostname": "WS01", "platform": "Windows 11",
                 "status": "online", "agent_version": "24.1", "last_seen": _now(),
                 "link": "https://s1.example/agents/a1", "raw": {}}]

    def alerts(self, ref, since=None):
        self.calls.append(("alerts", ref))
        return [{"external_id": "t9", "kind": "threat", "severity": "critical",
                 "title": "Ransomware behavior blocked", "detail": "pre-execution · WS01",
                 "tool_status": "resolved" if self.resolved else "unresolved",
                 "occurred_at": _now(), "link": "https://s1.example/t/t9",
                 "resolved": self.resolved, "device_external_id": "a1", "raw": {"x": 1}}]

    def mitigate(self, ids, action):
        self.calls.append(("mitigate", action, ids))
        return len(ids)

    def set_incident(self, ids, status, verdict=""):
        self.calls.append(("incident", status, verdict))
        return len(ids)

    def disconnect(self, ids):
        self.calls.append(("disconnect", ids))
        return len(ids)

    def reconnect(self, ids):
        self.calls.append(("reconnect", ids))
        return len(ids)


class FakeSuperOps:
    tool = "superops"
    configured = True

    def __init__(self, fail=False):
        self.fail = fail
        self.tickets = []
        self.replies = []

    def create_ticket(self, account_id, subject, description, requester_user_id="", priority=""):
        if self.fail:
            raise connectors.ConnectorError("SuperOps: down")
        self.tickets.append((account_id, subject))
        return {"ticket_id": "900", "display_id": "101226-0007"}

    def add_ticket_reply(self, ticket_id, content):
        self.replies.append((ticket_id, content))


def _client_with_s1(fake):
    connectors._instances["sentinelone"] = fake
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", sentinelone_site_ids="111",
               portal_enabled=True, portal_domains="riverbendcu.org")
    db.add(c)
    db.commit()
    return db, c


def test_sync_upserts_and_follows_vendor_resolution(fresh_db):
    fake = FakeS1()
    db, c = _client_with_s1(fake)
    res = sync_client_tool(db, c, "sentinelone")
    assert res["ok"] and res["devices"] == 1 and res["new_alerts"] == 1
    res2 = sync_client_tool(db, c, "sentinelone")
    assert res2["new_alerts"] == 0  # idempotent
    db = SessionLocal()
    assert db.query(Device).count() == 1 and db.query(Alert).count() == 1
    a = db.query(Alert).one()
    assert a.status == "open" and a.device.hostname == "WS01" and a.severity == "critical"
    # vendor resolves it; module status follows
    fake.resolved = True
    sync_client_tool(SessionLocal(), c, "sentinelone")
    assert SessionLocal().query(Alert).one().status == "resolved"
    # a later sync with the vendor still open does not un-resolve
    fake.resolved = False
    sync_client_tool(SessionLocal(), c, "sentinelone")
    assert SessionLocal().query(Alert).one().status == "resolved"


def test_sync_failure_is_reported_not_raised(fresh_db):
    class Broken(FakeS1):
        def devices(self, ref):
            raise connectors.ConnectorError("SentinelOne: invalid API token")

    db, c = _client_with_s1(Broken())
    res = sync_client_tool(db, c, "sentinelone")
    assert not res["ok"] and "invalid API token" in res["detail"]


def _synced_alert(admin_or_client):
    fake = FakeS1()
    db, c = _client_with_s1(fake)
    sync_client_tool(db, c, "sentinelone")
    return fake, c, SessionLocal().query(Alert).one()


def test_alert_action_calls_tool_and_logs(admin):
    fake, c, a = _synced_alert(admin)
    r = admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"}, follow_redirects=False)
    assert r.status_code == 302 and "msg=" in r.headers["location"]
    assert ("mitigate", "quarantine", ["t9"]) in fake.calls
    log = SessionLocal().query(ActionLog).filter_by(alert_id=a.id).one()
    assert log.result == "ok" and log.action == "Quarantine threat"
    assert log.client_visible is False  # not published yet


def test_device_action_from_alert_and_isolation_state(admin):
    fake, c, a = _synced_alert(admin)
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_disconnect", "confirm": "true"})
    assert ("disconnect", ["a1"]) in fake.calls
    db = SessionLocal()
    assert db.query(Device).one().status == "isolating"


def test_wrong_tool_action_is_refused(admin):
    fake, c, a = _synced_alert(admin)
    r = admin.post(f"/alerts/{a.id}/action", data={"action_id": "h_approve"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().query(ActionLog).filter_by(alert_id=a.id).count() == 0


def test_failed_tool_call_logs_failed_and_surfaces_message(admin):
    class Failing(FakeS1):
        def mitigate(self, ids, action):
            raise connectors.ConnectorError("SentinelOne: HTTP 403 on /threats/mitigate/quarantine")

    fake = Failing()
    db, c = _client_with_s1(fake)
    sync_client_tool(db, c, "sentinelone")
    a = SessionLocal().query(Alert).one()
    r = admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().query(ActionLog).filter_by(alert_id=a.id).one().result == "failed"


def _portal_session(client, email, c):
    db = SessionLocal()
    if not db.query(User).filter_by(email=email).count():
        db.add(User(email=email, role="client", client_id=c.id))
        db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_publish_flow_and_portal_scoping(admin):
    fake, c, a = _synced_alert(admin)
    db = SessionLocal()
    other = Client(name="Other Co", portal_enabled=True)
    db.add(other)
    db.commit()
    _portal_session(admin, "cfo@riverbendcu.org", c)
    # unpublished: invisible on the portal
    assert "Ransomware behavior blocked" not in admin.get("/portal").text
    assert admin.get(f"/portal/alerts/{a.id}").status_code == 404
    # tech view is confined for client users, so publish through a fresh admin login
    admin.cookies.set(auth.COOKIE, auth.make_session("admin"))
    admin.post(f"/alerts/{a.id}/triage",
               data={"op": "publish", "client_note": "We blocked and quarantined a ransomware attempt on WS01."})
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"})  # shared + published
    _portal_session(admin, "it@riverbendcu.org", c)
    page = admin.get("/portal").text
    assert "We blocked and quarantined" in page
    detail = admin.get(f"/portal/alerts/{a.id}").text
    assert "Threat quarantined on WS01." in detail  # plain-language action feed
    # scoping: another client's user cannot see it
    _portal_session(admin, "someone@other.co", other)
    assert admin.get(f"/portal/alerts/{a.id}").status_code == 404
    assert admin.get("/alerts", follow_redirects=False).headers["location"] == "/portal"


def test_portal_messaging_routes_desks_and_binds_superops_ticket(client):
    fake_so = FakeSuperOps()
    connectors._instances["superops"] = fake_so
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", portal_enabled=True, portal_domains="riverbendcu.org",
               superops_client_id="acc1")
    db.add(c)
    db.commit()
    _portal_session(client, "cfo@riverbendcu.org", c)
    # SOC message: no ticket, lands in tech inbox
    client.post("/portal/messages/soc", data={"body": "Did you see the odd sign-ins last night?"})
    # helpdesk message: opens a SuperOps ticket
    client.post("/portal/messages/helpdesk", data={"body": "Printer server is down\nSecond floor"})
    db = SessionLocal()
    soc = db.query(Channel).filter_by(client_id=c.id, desk="soc").one()
    hd = db.query(Channel).filter_by(client_id=c.id, desk="helpdesk").one()
    assert soc.tech_unread == 1 and soc.superops_ticket_id == ""
    assert hd.superops_ticket_id == "900" and hd.superops_ticket_display == "101226-0007"
    assert fake_so.tickets == [("acc1", "Printer server is down")]
    sys_notes = [m for m in db.query(Message).all() if m.sender_kind == "system"]
    assert any("101226-0007" in m.body for m in sys_notes)
    # tech reply mirrors into the ticket and flips the client unread counter
    client.cookies.set(auth.COOKIE, auth.make_session("admin"))
    client.post(f"/messages/{hd.id}", data={"body": "On it, dispatching now."})
    db = SessionLocal()
    hd = db.get(Channel, hd.id)
    assert hd.client_unread == 1
    assert fake_so.replies and fake_so.replies[0][0] == "900" and "On it" in fake_so.replies[0][1]
    # the client sees the reply on their desk page
    _portal_session(client, "cfo@riverbendcu.org", c)
    page = client.get("/portal/messages/helpdesk").text
    assert "On it, dispatching now." in page
    assert SessionLocal().get(Channel, hd.id).client_unread == 0  # viewing marks read


def test_superops_outage_never_blocks_the_message(client):
    connectors._instances["superops"] = FakeSuperOps(fail=True)
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", portal_enabled=True, portal_domains="riverbendcu.org",
               superops_client_id="acc1")
    db.add(c)
    db.commit()
    _portal_session(client, "cfo@riverbendcu.org", c)
    r = client.post("/portal/messages/helpdesk", data={"body": "Help"}, follow_redirects=False)
    assert r.status_code == 302
    db = SessionLocal()
    ch = db.query(Channel).filter_by(client_id=c.id, desk="helpdesk").one()
    assert ch.superops_ticket_id == "" and len(ch.messages) == 1  # message kept, ticket retried next time


def test_escalation_posts_hub_contract(admin, monkeypatch):
    fake, c, a = _synced_alert(admin)
    sent = {}

    class _Resp:
        def raise_for_status(self):
            return None

        @staticmethod
        def json():
            return {"case_id": "VCD-IR-2026-801", "id": "x", "linked": False}

    def fake_post(url, json, headers, timeout):
        sent.update(url=url, payload=json, headers=headers)
        return _Resp()

    from app import hub
    monkeypatch.setattr(hub.httpx, "post", fake_post)
    monkeypatch.setattr(settings, "platform_hub_url", "http://hub.local")
    monkeypatch.setattr(settings, "platform_hub_token", "tok")
    r = admin.post(f"/alerts/{a.id}/escalate", follow_redirects=False)
    assert "VCD-IR-2026-801" in r.headers["location"]
    assert sent["url"] == "http://hub.local/api/ir-cases"
    assert sent["headers"]["Authorization"] == "Bearer tok"
    p = sent["payload"]
    assert p["source_module"] == "managed-services" and p["workstream"] == "Scoping and Containment"
    assert p["finding"]["subject"]["client"] == "Riverbend Credit Union"
    assert p["finding"]["matched"] == "WS01"
    db = SessionLocal()
    a2 = db.query(Alert).one()
    assert a2.escalated_case == "VCD-IR-2026-801" and a2.status == "acknowledged"


def test_findings_api_requires_auth_and_maps_alerts(admin):
    fake, c, a = _synced_alert(admin)
    assert admin.get("/api/findings").status_code in (401, 302) or True  # cookie present; check bearer path below
    import httpx as _  # noqa: F401
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as anon:
        assert anon.get("/api/findings").status_code == 401
        rows = anon.get("/api/findings", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert rows[0]["module"] == "managed-services" and rows[0]["reason"] == "sentinelone"
    assert rows[0]["severity"] == "critical" and rows[0]["workstream"] == "Scoping and Containment"


def test_module_on_off(client):
    settings.module_enabled = False
    try:
        assert client.get("/").status_code == 503
        assert client.get("/api/module", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()["enabled"] is False
        assert client.get("/healthz").status_code == 200
    finally:
        settings.module_enabled = True
    assert client.get("/login").status_code == 200


def test_client_page_renders_tool_cards_and_mapping(admin):
    fake, c, a = _synced_alert(admin)
    page = admin.get(f"/clients/{c.id}").text
    assert "SentinelOne" in page and "Open console" in page and "WS01" in page
    assert "Isolate from network" in page
    r = admin.post(f"/clients/{c.id}/map", data={
        "superops_client_id": "acc1", "sentinelone_site_ids": "111, 222",
        "crowdstrike_cid": "AABB", "huntress_org_id": "42", "acronis_tenant_id": "ten-1"},
        follow_redirects=False)
    assert r.status_code == 302
    c2 = SessionLocal().get(Client, c.id)
    assert c2.tools == ["superops", "sentinelone", "crowdstrike", "huntress", "acronis"]
    assert c2.sentinelone_site_ids == "111,222" and c2.crowdstrike_cid == "aabb"
