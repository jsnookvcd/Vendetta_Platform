"""SABINE end to end against a mock platform: perception builds the queue, the
rules raise proposals at the policy's autonomy, auto actions go through module
APIs with SABINE named as the actor, high-risk actions are only ever handed off,
decisions execute, and everything lands in a chain that verifies."""
import datetime as dt
import json

import httpx
import pytest

from app import auth, brain, ledger, perception, policy, reach
from app.config import settings
from app.db import Brief, Proposal, SessionLocal, WorkItem

NOW = dt.datetime.now(dt.timezone.utc)
OLD = (NOW - dt.timedelta(hours=2)).isoformat()
FRESH = (NOW - dt.timedelta(minutes=5)).isoformat()

DIRECTORY = {
    "platform": {"base_url": "http://platform:8000", "token": "ptok", "public_url": "https://platform.example"},
    "incident-response": {"base_url": "http://incident-response:8000", "token": "irtok", "public_url": "https://ir.example"},
    "managed-services": {"base_url": "http://managed-services:8000", "token": "mstok", "public_url": "https://msp.example"},
    "dark-web-monitoring": {"base_url": "http://dark-web-monitoring:8000", "token": "dwtok", "public_url": "https://darkweb.example"},
    "vulnerability-management": {"base_url": "http://vulnerability-management:8000", "token": "vtok", "public_url": "https://vuln.example"},
}


def _finding(mod, fid, sev, title, pid="plat-rb", client="Riverbend Credit Union", created=OLD, **extra):
    return {"id": fid, "module": mod, "subject": {"client_id": "x", "platform_client_id": pid, "client": client, "case_ref": ""},
            "type": extra.pop("type", "finding"), "severity": sev, "status": "new", "title": title,
            "matched": extra.pop("matched", ""), "evidence": [], "workstream": "Scoping and Containment",
            "created_at": created, **extra}


class World:
    """A mock of the platform and modules, mutable so tests can change the picture."""

    def __init__(self):
        self.calls = []
        self.clients = [{"id": "plat-rb", "name": "Riverbend Credit Union"}, {"id": "plat-hp", "name": "Harbor Point"}]
        self.staff = {"governs": True, "staff": [
            {"email": "dan@vendettacd.io", "name": "Dan", "active": True, "platform_role": "admin",
             "modules": {"incident-response": {"role": "admin"}, "managed-services": {"role": "admin"}}},
            {"email": "idle@vendettacd.io", "name": "Idle", "active": True, "platform_role": "analyst",
             "modules": {"incident-response": {"role": "none"}}},
        ]}
        self.readiness = {"ready": False, "control_plane": {"checks": []}, "modules": [
            {"key": "dark-web-monitoring", "display_name": "Dark Web Monitoring", "checks": [
                {"label": "Roster from platform", "state": "fail", "detail": "last pull failed: platform rejected the token"}]},
        ]}
        self.findings = {
            "dark-web-monitoring": [_finding("dark-web-monitoring", "dw1", "critical", "rb combolist leak", matched="jdoe@riverbendcu.org")],
            "managed-services": [_finding("managed-services", "al1", "critical", "Ransomware behavior on WS01", type="threat", matched="WS01"),
                                 _finding("managed-services", "al2", "high", "jdoe@riverbendcu.org credential stuffing", matched="jdoe@riverbendcu.org", created=FRESH)],
            "vulnerability-management": [_finding("vulnerability-management", "v1", "high", "OpenSSL < 3.0.14", pid="plat-hp", client="Harbor Point",
                                                  native_status="remediating", created=(NOW - dt.timedelta(days=45)).isoformat())],
        }
        self.cases = [{"id": "c1", "number": "VCD-IR-2026-790", "title": "BEC at Harbor Point", "severity": "high",
                       "client": {"id": "h", "name": "Harbor Point", "platform_client_id": "plat-hp"}, "lead": "Dan",
                       "opened_at": (NOW - dt.timedelta(days=10)).isoformat(), "last_update_at": (NOW - dt.timedelta(days=8)).isoformat(),
                       "board": {"open": 3}, "workstreams": []}]
        self.escalations = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.url.host, req.method, req.url.path, req.headers.get("authorization"), req.headers.get("x-vendetta-actor")))
        host, path = req.url.host, req.url.path
        if host == "platform":
            if path == "/api/platform/clients":
                return httpx.Response(200, json={"clients": self.clients})
            if path == "/api/platform/staff":
                return httpx.Response(200, json=self.staff)
            if path == "/api/platform/readiness":
                return httpx.Response(200, json=self.readiness)
            if path == "/api/platform/modules":
                return httpx.Response(200, json={"modules": []})
        if path == "/api/module":
            return httpx.Response(200, json={"module": host, "enabled": True})
        if path == "/api/findings":
            return httpx.Response(200, json=self.findings.get(host, []))
        if path == "/api/ir-cases":
            return httpx.Response(200, json=self.cases)
        if path.startswith("/api/findings/") and path.endswith("/escalate"):
            fid = path.split("/")[3]
            self.escalations.append((host, fid))
            return httpx.Response(200, json={"escalated": True, "case": "VCD-IR-2026-801", "linked": False})
        if path == "/api/provision/sync":
            return httpx.Response(200, json={"ok": True, "roster": 2, "added": 0, "updated": 2, "deactivated": 0})
        return httpx.Response(404, json={"detail": "no route"})


@pytest.fixture()
def world(fresh_db, monkeypatch):
    w = World()
    monkeypatch.setattr(settings, "module_directory", json.dumps(DIRECTORY))
    monkeypatch.setattr(settings, "platform_url", "http://platform:8000")
    monkeypatch.setattr(settings, "platform_token", "ptok")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    reach.set_transport(httpx.MockTransport(w.handler))
    yield w
    reach.set_transport(None)


def test_cycle_builds_queue_proposes_and_acts_by_policy(world):
    db = SessionLocal()
    summary = brain.cycle(db)
    assert all(summary["seen"].values()), summary["seen"]
    # the queue carries the high-severity findings, the case and the red readiness item
    items = {w.key: w for w in db.query(WorkItem).all()}
    assert "finding:dark-web-monitoring:dw1" in items and "case:incident-response:c1" in items
    assert "readiness:dark-web-monitoring:Roster from platform" in items
    assert items["finding:dark-web-monitoring:dw1"].link == "https://darkweb.example/hits/dw1"
    assert "overdue:vulnerability-management:v1" in items  # 45 days old, high SLA is 30

    props = {p.key: p for p in db.query(Proposal).all()}
    # escalation of the old critical dark web finding is proposed (policy: propose), not executed
    e = props["escalate_finding:dark-web-monitoring:dw1"]
    assert e.status == "pending" and e.risk == "medium" and e.autonomy == "propose" and "120 minutes" in e.rationale
    # the fresh high alert (5 minutes) is below the threshold: no proposal
    assert "escalate_finding:managed-services:al2" not in props
    # correlation across dark web and managed services on the shared credential, auto, queued as SABINE work
    corr = [p for k, p in props.items() if k.startswith("correlate:plat-rb")]
    assert corr and corr[0].status == "executed" and "jdoe@riverbendcu.org" in corr[0].rationale
    assert any(w.source == "sabine" and w.kind == "correlation" for w in items.values()) or \
        any(w.source == "sabine" and w.kind == "correlation" for w in db.query(WorkItem).all())
    # host action for the ransomware alert: high risk, pending, never executed
    h = props["host_action:al1"]
    assert h.status == "pending" and h.risk == "high" and h.target["link"] == "https://msp.example/alerts/al1"
    # admin: failed roster pull was re-synced automatically through the module's API
    rs = props["roster_sync:dark-web-monitoring"]
    assert rs.status == "executed" and rs.result["ok"]
    assert ("dark-web-monitoring", "POST", "/api/provision/sync", "Bearer dwtok", "sabine") in world.calls
    # staff hygiene: Idle has no grants; nobody is granted vulnerability-management
    assert props["staff:nogrants:idle@vendettacd.io"].status == "executed"
    assert props["staff:nobody:vulnerability-management"].status == "executed"
    # services: the quiet case and the overdue remediation were raised; briefs written
    assert props["stale_case:c1"].status == "executed" and "8 days" in props["stale_case:c1"].title
    assert any(k.startswith("remediation_overdue:") for k in props)
    briefs = db.query(Brief).all()
    assert {b.kind for b in briefs} == {"client-brief", "daily-summary"}
    rb = next(b for b in briefs if b.client == "Riverbend Credit Union")
    assert "rb combolist leak" in rb.body_md and rb.source == "rules"
    # nothing SABINE did touched a host: the only module writes were escalate-free and the sync
    assert world.escalations == []
    # the chain verifies and carries proposals, actions and the cycle
    v = ledger.verify(db)
    assert v["ok"] and v["length"] > 5


def test_second_cycle_is_idempotent_and_marks_gone(world):
    db = SessionLocal()
    brain.cycle(db)
    n_props = db.query(Proposal).count()
    brain.cycle(db)
    assert db.query(Proposal).count() == n_props  # pending and recently executed ones are not re-raised
    # the finding gets handled in its module: it leaves the queue
    world.findings["dark-web-monitoring"] = []
    brain.cycle(db)
    assert db.query(WorkItem).filter_by(key="finding:dark-web-monitoring:dw1").one().state == "gone"


def test_approval_executes_through_the_module_api_as_sabine(world):
    db = SessionLocal()
    brain.cycle(db)
    p = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    res = brain.decide(db, p, "dan@vendettacd.io", True, "confirmed with client")
    assert res["ok"] and res["case"] == "VCD-IR-2026-801"
    assert ("dark-web-monitoring", "dw1") in world.escalations
    assert ("dark-web-monitoring", "POST", "/api/findings/dw1/escalate", "Bearer dwtok", "sabine") in world.calls
    p = db.get(Proposal, p.id)
    assert p.status == "executed" and p.decided_by == "dan@vendettacd.io"
    # a second decision is refused
    assert brain.decide(db, p, "dan@vendettacd.io", True)["ok"] is False
    kinds = [r.kind for r in db.query(ledger.Ledger).order_by(ledger.Ledger.chain_seq).all()]
    assert "decision" in kinds and kinds.count("action") >= 1 and ledger.verify(db)["ok"]


def test_rejection_and_high_risk_handoff(world):
    db = SessionLocal()
    brain.cycle(db)
    h = db.query(Proposal).filter_by(key="host_action:al1").one()
    res = brain.decide(db, h, "dan@vendettacd.io", True)
    assert res["ok"] and "handed to a responder" in res["detail"]
    assert world.escalations == [] and not any(c[2].startswith("/devices") for c in world.calls)
    w = db.query(WorkItem).filter(WorkItem.source == "sabine", WorkItem.kind == "correlation").first()
    assert w is not None
    e = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    assert brain.decide(db, e, "dan@vendettacd.io", False, "false positive")["detail"] == "rejected"
    assert db.get(Proposal, e.id).status == "rejected"


def test_autonomy_policy_is_enforced(world):
    db = SessionLocal()
    policy.set_autonomy(db, "escalate_finding", "auto", "admin")
    policy.set_autonomy(db, "staff_hygiene", "off", "admin")
    with pytest.raises(ValueError):
        policy.set_autonomy(db, "host_action", "auto", "admin")  # high risk can never be auto
    brain.cycle(db)
    e = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    assert e.status == "executed" and e.autonomy == "auto" and ("dark-web-monitoring", "dw1") in world.escalations
    assert db.query(Proposal).filter(Proposal.action == "staff_hygiene").count() == 0


def test_module_down_degrades_not_breaks(world):
    db = SessionLocal()
    real = world.handler

    def flaky(req):
        if req.url.host == "vulnerability-management":
            raise httpx.ConnectError("down")
        return real(req)
    reach.set_transport(httpx.MockTransport(flaky))
    summary = brain.cycle(db)
    assert summary["seen"]["module:vulnerability-management"] is False
    assert db.query(Proposal).filter_by(key="unreachable:vulnerability-management").one().status == "executed"
    assert summary["queue"]["finding"] >= 2  # the others still flowed


def test_console_and_api(client, world):
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    assert client.post("/run", follow_redirects=False).status_code == 302
    for path in ("/", "/queue", "/queue?domain=admin", "/proposals", "/proposals?status=all", "/policy", "/briefs", "/ledger", "/ask", "/settings"):
        r = client.get(path)
        assert r.status_code == 200, path
    pid = db_first_pending()
    assert client.get(f"/proposals/{pid}").status_code == 200
    r = client.post(f"/proposals/{pid}/decide", data={"approve": "false", "note": "no"}, follow_redirects=False)
    assert r.status_code == 302
    assert client.post("/policy/escalate_finding", data={"autonomy": "auto"}, follow_redirects=False).status_code == 302
    bearer = {"Authorization": f"Bearer {auth.api_token()}"}
    assert client.get("/api/queue", headers=bearer).json()
    assert client.get("/api/module", headers=bearer).json()["readiness"]["integrations"]["kind"] == "agent"
    assert client.get("/api/ledger/verify", headers=bearer).json()["ok"]
    r = client.post("/ask", data={"question": "what is open?"})
    assert r.status_code == 200 and "open items" in r.text
    # an API caller cannot decide a high-risk proposal
    h = SessionLocal().query(Proposal).filter_by(key="host_action:al1").one()
    assert client.post(f"/api/proposals/{h.id}/decide", json={"approve": True}, headers=bearer).status_code == 403


def db_first_pending() -> str:
    return SessionLocal().query(Proposal).filter_by(status="pending").first().id
