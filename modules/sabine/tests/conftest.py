"""Tests run against a real Postgres. Point SABINE_TEST_DATABASE_URL at a
disposable database; tests drop and recreate its tables. Skipped if unreachable."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
TEST_DB = os.environ.get("SABINE_TEST_DATABASE_URL",
                         "postgresql+psycopg://sabine:sabine@localhost:5432/sabine_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("SECRET_KEY", "test-secret")
# No scheduler threads in tests; cycles run explicitly.
os.environ.setdefault("CYCLE_INTERVAL_SECONDS", "0")
os.environ.setdefault("PROVISION_INTERVAL_SECONDS", "0")

import bcrypt  # noqa: E402

os.environ["ADMIN_PASSWORD_HASH"] = bcrypt.hashpw(b"pw", bcrypt.gensalt(4)).decode()


def _db_up() -> bool:
    try:
        from sqlalchemy import create_engine, text
        with create_engine(TEST_DB).connect() as c:
            c.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _release(engine):
    from sqlalchemy.orm import close_all_sessions
    close_all_sessions()
    engine.dispose()


@pytest.fixture()
def fresh_db():
    if not _db_up():
        pytest.skip("test database not reachable")
    from app import metrics
    from app.db import Base, engine, init_db
    _release(engine)
    Base.metadata.drop_all(engine)
    init_db()
    metrics.invalidate()
    yield
    _release(engine)


@pytest.fixture()
def client(fresh_db):
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as tc:
        yield tc


@pytest.fixture()
def admin(client):
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    return client


# ---------------------------------------------------------------- the mocked world
# A mock of the platform and every module SABINE reaches, mutable so tests can
# change the picture. test_brain re-exports `world` for the older test modules.
import datetime as dt  # noqa: E402
import json  # noqa: E402

import httpx  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
OLD = (NOW - dt.timedelta(hours=2)).isoformat()
FRESH = (NOW - dt.timedelta(minutes=5)).isoformat()

DIRECTORY = {
    "platform": {"base_url": "http://platform:8000", "token": "ptok", "public_url": "https://platform.example"},
    "incident-response": {"base_url": "http://incident-response:8000", "token": "irtok", "public_url": "https://ir.example"},
    "managed-services": {"base_url": "http://managed-services:8000", "token": "mstok", "public_url": "https://msp.example"},
    "dark-web-monitoring": {"base_url": "http://dark-web-monitoring:8000", "token": "dwtok", "public_url": "https://darkweb.example"},
    "vulnerability-management": {"base_url": "http://vulnerability-management:8000", "token": "vtok", "public_url": "https://vuln.example"},
    "professional-services": {"base_url": "http://professional-services:8000", "token": "osptok", "public_url": "https://osp.example"},
    "mdr": {"base_url": "http://mdr:8800", "token": "mdrtok", "public_url": "https://mdr.example"},
    "project-management": {"base_url": "http://project-management:8000", "token": "pmtok",
                           "public_url": "https://pm.example"},
}


def _finding(mod, fid, sev, title, pid="plat-rb", client="Riverbend Credit Union", created=OLD, **extra):
    return {"id": fid, "module": mod, "subject": {"client_id": "x", "platform_client_id": pid, "client": client, "case_ref": ""},
            "type": extra.pop("type", "finding"), "severity": sev, "status": extra.pop("status", "new"), "title": title,
            "matched": extra.pop("matched", ""), "evidence": [], "workstream": "Scoping and Containment",
            "created_at": created, **extra}


def _investigation(fid, sev, title, number, opened, pid="plat-rb", client="Riverbend Credit Union", **extra):
    """The MDR finding shape: the contract finding plus native_status, verdict, mitre,
    opened/acknowledged/contained timestamps, response, rule and signal count."""
    return _finding("mdr", fid, sev, title, pid=pid, client=client, created=opened, type="investigation",
                    native_status=extra.pop("native_status", "new"), verdict=extra.pop("verdict", "pending"),
                    mitre=["T1486"], opened_at=opened, acknowledged_at=extra.pop("acknowledged_at", None),
                    contained_at=extra.pop("contained_at", None),
                    response={"action": "isolate_host", "host": extra.get("matched", ""),
                              "alert_ref": extra.pop("alert_ref", f"ms-{fid}")},
                    rule=extra.pop("rule", "ransomware-behavior"), signals=extra.pop("signals", 2), number=number, **extra)


class World:
    """The platform (clients with tier and commitments, staff, readiness, the
    Security Journey and communications), the finding modules, MDR (investigations,
    closed history, suppressions), the IR hub (cases, on-call page) and OSP."""

    def __init__(self):
        self.calls = []
        self.clients = [
            {"id": "plat-rb", "name": "Riverbend Credit Union", "tier": "advanced", "account_lead": "dan@vendettacd.io",
             "commitments": {"critical_ack_minutes": 10, "critical_contain_minutes": 120},
             "services": ["dark-web-monitoring", "managed-services", "mdr", "professional-services"]},
            {"id": "plat-hp", "name": "Harbor Point", "tier": "core", "account_lead": "",
             "commitments": {"critical_ack_minutes": 15, "critical_contain_minutes": 240},
             "services": ["vulnerability-management", "incident-response", "professional-services"]},
        ]
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
                                 _finding("managed-services", "al2", "high", "jdoe@riverbendcu.org credential stuffing", matched="jdoe@riverbendcu.org", created=FRESH),
                                 # the module's triage copilot has spoken on these two; no human has decided yet
                                 _finding("managed-services", "al3", "critical", "Scheduled task created by admin tool", matched="SRV02",
                                          copilot={"verdict": "false_positive", "confidence": 0.95, "model": "rules-v1", "requires_approval": True,
                                                   "rationale": "a human previously dispositioned this asset/signature as false positive.",
                                                   "created_at": OLD, "decision": None}),
                                 _finding("managed-services", "al4", "high", "Credential dumping on FS01", matched="FS01",
                                          copilot={"verdict": "true_positive", "confidence": 0.9, "model": "rules-v1", "requires_approval": False,
                                                   "rationale": "high severity; carries a CVE identifier.", "created_at": OLD, "decision": None})],
            "vulnerability-management": [_finding("vulnerability-management", "v1", "high", "OpenSSL < 3.0.14", pid="plat-hp", client="Harbor Point",
                                                  native_status="remediating", created=(NOW - dt.timedelta(days=45)).isoformat())],
            # MDR: one critical investigation for Riverbend opened 40 minutes ago, never
            # acknowledged (the advanced tier commits to 10 minutes).
            "mdr": [_investigation("i1", "critical", "Ransomware behavior on WS01", "MDR-2026-0007",
                                   (NOW - dt.timedelta(minutes=40)).isoformat(), matched="WS01")],
        }
        # MDR's closed investigations: two "scheduled task" detections people closed as noise.
        self.mdr_closed = [
            _investigation(f"x{n}", "medium", f"Scheduled task created by admin tool on SRV0{n}", f"MDR-2026-000{n}",
                           (NOW - dt.timedelta(days=n + 2)).isoformat(), matched=f"SRV0{n}", native_status="closed",
                           verdict="false_positive", rule="schtask")
            for n in (1, 2)]
        self.suppressions = []
        self.cases = [{"id": "c1", "number": "VCD-IR-2026-790", "title": "BEC at Harbor Point", "severity": "high",
                       "client": {"id": "h", "name": "Harbor Point", "platform_client_id": "plat-hp"}, "lead": "Dan",
                       "opened_at": (NOW - dt.timedelta(days=10)).isoformat(), "last_update_at": (NOW - dt.timedelta(days=8)).isoformat(),
                       "board": {"open": 3}, "workstreams": []}]
        # Office of Special Projects: one vCISO retainer with a deliverable the client has
        # not accepted for 12 days and one past its planned end; one fresh delivery.
        self.engagements = [
            {"id": "e1", "module": "professional-services", "name": "vCISO Retainer", "kind": "vciso", "status": "active",
             "lead": "Jordan", "progress": 50, "published": True, "ends_on": None, "created_at": OLD,
             "subject": {"client_id": "x", "platform_client_id": "plat-rb", "client": "Riverbend Credit Union"},
             "deliverables": [
                 {"id": "d1", "title": "Information Security Policy v1", "kind": "policy", "status": "delivered",
                  "delivered_at": (NOW - dt.timedelta(days=12)).isoformat(), "accepted_at": None},
                 {"id": "d2", "title": "IR Playbook", "kind": "playbook", "status": "delivered",
                  "delivered_at": (NOW - dt.timedelta(days=2)).isoformat(), "accepted_at": None},
                 {"id": "d3", "title": "Kickoff", "kind": "session", "status": "accepted",
                  "delivered_at": OLD, "accepted_at": OLD}]},
            {"id": "e2", "module": "professional-services", "name": "Tabletop 2026", "kind": "tabletop", "status": "active",
             "lead": "", "progress": 0, "published": False, "ends_on": (NOW - dt.timedelta(days=9)).isoformat(), "created_at": OLD,
             "subject": {"client_id": "y", "platform_client_id": "plat-hp", "client": "Harbor Point"}, "deliverables": []},
        ]
        self.escalations = []
        self.journey: dict[str, list[dict]] = {"plat-rb": [], "plat-hp": []}
        self.communications: dict[str, list[dict]] = {"plat-rb": [], "plat-hp": []}
        self.pages = []
        self.page_sent = {"teams": "sent"}
        self.pm_alerts = [
            {"key": "burn_over:eng1", "kind": "burn_over", "severity": "high",
             "title": "VCD-IR-2026-001 is over budget: 52.0h of 40h (130%)", "detail": "", "owner": "pm@vendettacd.io",
             "link": "/engagements/eng1", "first_seen": OLD, "engagement": "VCD-IR-2026-001",
             "client": "Riverbend Credit Union", "platform_client_id": "plat-rb", "practice": "ir"},
            {"key": "task_due_soon:c9", "kind": "task_due_soon", "severity": "low", "title": "Due tomorrow: #9",
             "detail": "", "owner": "pm@vendettacd.io", "link": "/tasks/9", "first_seen": FRESH,
             "engagement": "VCD-IR-2026-001", "client": "Riverbend Credit Union", "platform_client_id": "plat-rb",
             "practice": "ir"}]
        self._n = 0

    # ------------------------------------------------------------ platform helpers
    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}{self._n}"

    def _client(self, pid: str):
        return next((c for c in self.clients if c["id"] == pid), None)

    def journey_item(self, pid: str, title: str, status: str = "planned", source_ref: str = "", source: str = "staff", **extra) -> dict:
        item = {"id": self._id("j"), "title": title, "detail": extra.pop("detail", ""), "area": extra.pop("area", "governance"),
                "status": status, "due_on": None, "source": source, "source_ref": source_ref, "note": "",
                "created_at": OLD, "updated_at": OLD, "decided_by": "", **extra}
        self.journey.setdefault(pid, []).append(item)
        return item

    def _platform(self, req: httpx.Request, path: str):
        parts = path.strip("/").split("/")  # api platform clients <pid> journey|communications [...]
        if len(parts) < 5 or parts[:3] != ["api", "platform", "clients"]:
            return None
        pid, what = parts[3], parts[4]
        c = self._client(pid)
        if c is None:
            return httpx.Response(404, json={"detail": "unknown client"})
        body = json.loads(req.content or b"{}") if req.method == "POST" else {}
        if what == "journey" and len(parts) == 5:
            items = self.journey.setdefault(pid, [])
            if req.method == "GET":
                return httpx.Response(200, json={"client": {"id": pid, "name": c["name"]}, "items": items})
            if body.get("area") not in ("identity", "endpoint", "cloud", "email", "network", "data", "vulnerability",
                                        "response", "governance", "awareness") or not (body.get("title") or "").strip():
                return httpx.Response(400, json={"detail": "bad area or empty title"})
            ref = body.get("source_ref") or ""
            hit = next((i for i in items if ref and i["source_ref"] == ref), None)
            if hit:
                return httpx.Response(200, json={"id": hit["id"], "created": False})
            item = self.journey_item(pid, body["title"], status="proposed", source_ref=ref, source="sabine",
                                     detail=body.get("detail", ""), area=body["area"], due_on=body.get("due_on"))
            return httpx.Response(200, json={"id": item["id"], "created": True})
        if what == "journey" and len(parts) == 7 and parts[6] == "progress":
            item = next((i for i in self.journey.get(pid, []) if i["id"] == parts[5]), None)
            if item is None:
                return httpx.Response(404, json={"detail": "unknown item"})
            if item["status"] in ("proposed", "declined") or body.get("status") not in ("in_progress", "done"):
                return httpx.Response(409, json={"detail": "only a person accepts a proposal"})
            item["status"], item["note"], item["updated_at"] = body["status"], body.get("note", ""), NOW.isoformat()
            return httpx.Response(200, json={"id": item["id"], "status": item["status"]})
        if what == "communications" and len(parts) == 5:
            items = self.communications.setdefault(pid, [])
            if req.method == "GET":
                return httpx.Response(200, json={"items": list(reversed(items))})
            ref = body.get("source_ref") or ""
            hit = next((i for i in items if ref and i["source_ref"] == ref), None)
            if hit:
                return httpx.Response(200, json={"id": hit["id"], "created": False})
            item = {"id": self._id("m"), "kind": body["kind"], "title": body["title"], "subject": body.get("subject", ""),
                    "body_md": body.get("body_md", ""), "status": "draft", "source": "sabine", "source_ref": ref,
                    "created_at": NOW.isoformat(), "decided_by": "", "decided_at": None, "sent_detail": "", "published": False}
            items.append(item)
            return httpx.Response(200, json={"id": item["id"], "created": True})
        return None

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
            r = self._platform(req, path)
            if r is not None:
                return r
        if path == "/api/module":
            return httpx.Response(200, json={"module": host, "enabled": True})
        if host == "mdr" and path == "/api/findings" and req.url.params.get("status") == "all":
            return httpx.Response(200, json=self.findings.get("mdr", []) + self.mdr_closed)
        if path == "/api/findings":
            return httpx.Response(200, json=self.findings.get(host, []))
        if host == "mdr" and path == "/api/suppressions":
            if req.method == "GET":
                return httpx.Response(200, json=self.suppressions)
            body = json.loads(req.content)
            if not self._client(body.get("platform_client_id", "")):
                return httpx.Response(404, json={"detail": "unknown client"})
            s = {"id": self._id("s"), "platform_client_id": body["platform_client_id"],
                 "match": {"title_contains": body.get("title_contains"), "tool": body.get("tool"), "host": body.get("host")},
                 "reason": body["reason"], "created_by": body.get("created_by", ""), "created_at": NOW.isoformat(), "hits": 0,
                 "expires_at": (NOW + dt.timedelta(days=int(body.get("days") or 30))).isoformat()}
            self.suppressions.append(s)
            return httpx.Response(200, json={"id": s["id"], "expires_at": s["expires_at"]})
        if host == "incident-response" and path == "/api/oncall/page":
            self.pages.append(json.loads(req.content))
            return httpx.Response(200, json={"sent": dict(self.page_sent)})
        if path == "/api/ir-cases":
            return httpx.Response(200, json=self.cases)
        if host == "project-management" and path == "/api/alerts":
            return httpx.Response(200, json={"alerts": self.pm_alerts})
        if path == "/api/engagements":
            assert req.url.params["status"] == "open"
            return httpx.Response(200, json=self.engagements)
        if path.startswith("/api/findings/") and path.endswith("/escalate"):
            fid = path.split("/")[3]
            self.escalations.append((host, fid))
            return httpx.Response(200, json={"escalated": True, "case": "VCD-IR-2026-801", "linked": False})
        if path == "/api/provision/sync":
            return httpx.Response(200, json={"ok": True, "roster": 2, "added": 0, "updated": 2, "deactivated": 0})
        return httpx.Response(404, json={"detail": "no route"})


@pytest.fixture()
def world(fresh_db, monkeypatch):
    from app import business, reach
    from app.config import settings

    w = World()
    monkeypatch.setattr(settings, "module_directory", json.dumps(DIRECTORY))
    monkeypatch.setattr(settings, "platform_url", "http://platform:8000")
    monkeypatch.setattr(settings, "platform_token", "ptok")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.setattr(settings, "harvest_account_id", "")
    monkeypatch.setattr(settings, "harvest_token", "")
    monkeypatch.setattr(settings, "hubspot_token", "")
    reach.set_transport(httpx.MockTransport(w.handler))
    yield w
    reach.set_transport(None)
    business.set_transport(None)


# ---------------------------------------------------------------- Harvest and HubSpot
class BusinessWorld:
    """Harvest API v2 and HubSpot CRM v3/v4, enough for the four business skills."""

    def __init__(self):
        self.calls = []
        today = NOW.date()
        self.projects = [
            {"project_id": 101, "project_name": "Riverbend vCISO", "client_name": "Riverbend Credit Union", "budget_by": "project_cost",
             "budget": 20000.0, "budget_spent": 17000.0, "budget_remaining": 3000.0, "is_active": True},
            {"project_id": 102, "project_name": "Harbor Point IR retainer", "client_name": "Harbor Point", "budget_by": "project",
             "budget": 100.0, "budget_spent": 40.0, "budget_remaining": 60.0, "is_active": True},
            {"project_id": 103, "project_name": "Internal", "client_name": "Vendetta", "budget_by": "none",
             "budget": None, "budget_spent": 0, "budget_remaining": None, "is_active": True},
        ]
        self.users = [
            {"id": 1, "first_name": "Dan", "last_name": "Baker", "email": "dan@vendettacd.io", "weekly_capacity": 144000, "is_active": True},
            {"id": 2, "first_name": "Kim", "last_name": "Lee", "email": "kim@vendettacd.io", "weekly_capacity": 144000, "is_active": True},
        ]
        self.hours = [{"user_id": 1, "user_name": "Dan Baker", "total_hours": 46.5}, {"user_id": 2, "user_name": "Kim Lee", "total_hours": 20.0}]
        self.renewals = [
            {"id": "501", "properties": {"dealname": "Riverbend renewal 2027", "dealstage": "contractsent",
                                         "closedate": (today + dt.timedelta(days=21)).isoformat() + "T00:00:00Z", "amount": "48000",
                                         "pipeline": "renewals", "dealtype": "renewal"}}]
        self.won = [
            {"id": "601", "properties": {"dealname": "Lakeside MDR", "dealstage": "closedwon",
                                         "closedate": (today - dt.timedelta(days=6)).isoformat() + "T00:00:00Z", "amount": "36000",
                                         "pipeline": "default", "dealtype": "newbusiness", "hs_is_closed_won": "true"}},
            {"id": "602", "properties": {"dealname": "Harbor Point add-on", "dealstage": "closedwon",
                                         "closedate": (today - dt.timedelta(days=5)).isoformat() + "T00:00:00Z", "amount": "9000",
                                         "pipeline": "default", "dealtype": "existingbusiness", "hs_is_closed_won": "true"}},
            {"id": "603", "properties": {"dealname": "Fresh win", "dealstage": "closedwon",
                                         "closedate": (today - dt.timedelta(days=1)).isoformat() + "T00:00:00Z", "amount": "1000",
                                         "pipeline": "default", "dealtype": "newbusiness", "hs_is_closed_won": "true"}},
        ]
        self.companies = {"501": ("901", "Riverbend Credit Union"), "601": ("902", "Lakeside Bank, Inc."),
                          "602": ("903", "Harbor Point"), "603": ("904", "Fresh Co")}

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.url.host, req.method, req.url.path, dict(req.headers), req.content))
        host, path = req.url.host, req.url.path
        if host == "api.harvestapp.com":
            if req.headers.get("harvest-account-id") != "12345" or req.headers.get("authorization") != "Bearer hv-token":
                return httpx.Response(401, json={"error": "invalid_token"})
            if path == "/v2/reports/project_budget":
                return httpx.Response(200, json={"results": self.projects, "next_page": None})
            if path == "/v2/users":
                return httpx.Response(200, json={"users": self.users, "next_page": None})
            if path == "/v2/reports/time/team":
                return httpx.Response(200, json={"results": self.hours, "next_page": None})
        if host == "api.hubapi.com":
            if req.headers.get("authorization") != "Bearer hs-token":
                return httpx.Response(401, json={"message": "auth"})
            body = json.loads(req.content or b"{}")
            if path == "/crm/v3/objects/deals/search":
                flat = [f for g in body["filterGroups"] for f in g["filters"]]
                won = any(f["propertyName"] == "hs_is_closed_won" for f in flat)
                return httpx.Response(200, json={"results": self.won if won else self.renewals})
            if path == "/crm/v4/associations/deals/companies/batch/read":
                return httpx.Response(200, json={"results": [
                    {"from": {"id": i["id"]}, "to": [{"toObjectId": self.companies[i["id"]][0]}]}
                    for i in body["inputs"] if i["id"] in self.companies]})
            if path == "/crm/v3/objects/companies/batch/read":
                names = {cid: n for cid, n in self.companies.values()}
                return httpx.Response(200, json={"results": [{"id": i["id"], "properties": {"name": names[i["id"]]}} for i in body["inputs"]]})
        return httpx.Response(404, json={"detail": "no route"})


@pytest.fixture()
def biz(world, monkeypatch):
    from app import business
    from app.config import settings

    b = BusinessWorld()
    monkeypatch.setattr(settings, "harvest_account_id", "12345")
    monkeypatch.setattr(settings, "harvest_token", "hv-token")
    monkeypatch.setattr(settings, "hubspot_token", "hs-token")
    business.set_transport(httpx.MockTransport(b.handler))
    yield b
    business.set_transport(None)
