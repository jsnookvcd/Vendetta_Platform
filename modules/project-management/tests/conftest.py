"""Tests run against a real Postgres. Point PM_TEST_DATABASE_URL at a disposable
database; tests drop and recreate its tables. Skipped if unreachable.

Harvest and Microsoft Graph are replaced by in-memory fakes behind
httpx.MockTransport, so the tests exercise the real request code."""
import base64
import hashlib
import json
import os
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
TEST_DB = os.environ.get("PM_TEST_DATABASE_URL", "postgresql+psycopg://pmtool:pmtool@localhost:5432/pmtool_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["PUBLIC_URL"] = "https://pm.test.example"
os.environ["SHAREPOINT_RETRY_SECONDS"] = "0"

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
    from sqlalchemy import text

    from app.db import Base, engine, init_db
    _release(engine)
    Base.metadata.drop_all(engine)
    with engine.begin() as c:
        c.execute(text("DROP SEQUENCE IF EXISTS card_ref_seq"))
    init_db()
    yield
    _release(engine)


@pytest.fixture()
def client(fresh_db):
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app, base_url="https://pm.test.example") as tc:
        yield tc


@pytest.fixture()
def admin(client):
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    return client


def add_user(email: str, role: str = "analyst", active: bool = True):
    from app.db import SessionLocal, User
    db = SessionLocal()
    db.add(User(email=email, role=role, active=active, source="platform"))
    db.commit()
    db.close()


def as_user(client, email: str):
    from app import auth
    client.cookies.set(auth.COOKIE, auth.make_session(email))
    return client


# ---------------------------------------------------------------- fake Harvest
class FakeHarvest:
    def __init__(self):
        self.users = [{"id": 11, "email": "pm@vendettacd.io", "name": "Pat PM"},
                      {"id": 12, "email": "dan@vendettacd.io", "name": "Dan IR"},
                      {"id": 13, "email": "admin", "name": "Admin"}]
        self.projects = [{"id": 501, "name": "IFB Incident Response", "code": "IFB-IR", "client": {"name": "IFB"},
                          "budget": 120, "budget_by": "project", "is_billable": True},
                         {"id": 502, "name": "Rize vCISO", "code": "RIZE", "client": {"name": "Rize CU"}}]
        self.tasks = {501: [{"task": {"id": 901, "name": "Forensic Analysis"}, "billable": True},
                            {"task": {"id": 902, "name": "Project Management"}, "billable": True}],
                      502: [{"task": {"id": 903, "name": "Advisory"}, "billable": True}]}
        self.entries: dict[int, dict] = {}
        self.next_id = 7000
        self.requests: list[httpx.Request] = []

    def _entry(self, e):
        u = next(x for x in self.users if x["id"] == e["user_id"])
        p = next(x for x in self.projects if x["id"] == e["project_id"])
        t = next(x["task"] for x in self.tasks[e["project_id"]] if x["task"]["id"] == e["task_id"])
        return {"id": e["id"], "spent_date": e["spent_date"], "hours": e["hours"], "notes": e.get("notes", ""),
                "user": {"id": u["id"], "name": u["name"]}, "project": {"id": p["id"], "name": p["name"]},
                "task": t, "client": p["client"], "billable": True, "is_locked": e.get("is_locked", False),
                "is_running": False}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["Harvest-Account-Id"] == "acct-1"
        assert request.headers["Authorization"] == "Bearer hv-token"
        path = request.url.path.replace("/v2/", "", 1).strip("/")
        q = dict(request.url.params)
        if path == "users":
            return httpx.Response(200, json={"users": self.users, "links": {"next": None}})
        if path == "projects":
            return httpx.Response(200, json={"projects": self.projects, "links": {"next": None}})
        if path.startswith("projects/") and path.endswith("task_assignments"):
            pid = int(path.split("/")[1])
            return httpx.Response(200, json={"task_assignments": self.tasks.get(pid, []), "links": {"next": None}})
        if path.startswith("projects/"):
            pid = int(path.split("/")[1])
            p = next((x for x in self.projects if x["id"] == pid), None)
            return httpx.Response(200, json=p) if p else httpx.Response(404)
        if path == "time_entries" and request.method == "POST":
            body = json.loads(request.content)
            self.next_id += 1
            e = {"id": self.next_id, **body}
            self.entries[e["id"]] = e
            return httpx.Response(201, json=self._entry(e))
        if path == "time_entries":
            rows = list(self.entries.values())
            if "user_id" in q:
                rows = [e for e in rows if str(e["user_id"]) == q["user_id"]]
            if "project_id" in q:
                rows = [e for e in rows if str(e["project_id"]) == q["project_id"]]
            if "from" in q:
                rows = [e for e in rows if e["spent_date"] >= q["from"]]
            return httpx.Response(200, json={"time_entries": [self._entry(e) for e in rows], "links": {"next": None}})
        if path.startswith("time_entries/"):
            eid = int(path.split("/")[1])
            if eid not in self.entries:
                return httpx.Response(404)
            if request.method == "GET":
                return httpx.Response(200, json=self._entry(self.entries[eid]))
            if request.method == "PATCH":
                self.entries[eid].update(json.loads(request.content))
                return httpx.Response(200, json=self._entry(self.entries[eid]))
            if request.method == "DELETE":
                del self.entries[eid]
                return httpx.Response(200)
        return httpx.Response(404)


@pytest.fixture()
def fake_harvest(fresh_db):
    from app import harvest, integrations
    fake = FakeHarvest()
    harvest.TRANSPORT = httpx.MockTransport(fake.handler)
    harvest._USERS.update(at=0.0, by_email={})
    integrations.save({"harvest_account_id": "acct-1", "harvest_token": "hv-token"}, "test")
    yield fake
    harvest.TRANSPORT = None


# ---------------------------------------------------------------- fake Graph
class FakeGraph:
    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.fail = False
        self.puts: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "login.microsoftonline.com" in url:
            return httpx.Response(200, json={"access_token": "graph-token", "expires_in": 3600})
        assert request.headers.get("authorization") == "Bearer graph-token"
        if request.method == "GET" and "/sites/" in url:
            return httpx.Response(200, json={"id": "site-123"})
        if request.method == "PUT":
            if self.fail:
                return httpx.Response(403)
            self.puts.append(request.url.path)
            item_id = f"item-{len(self.files) + 1}"
            if "/items/" in request.url.path:
                item_id = request.url.path.split("/items/")[1].split("/")[0]
            self.files[item_id] = request.content
            return httpx.Response(201, json={"id": item_id, "webUrl": f"https://sp.example/{item_id}"})
        return httpx.Response(404)


@pytest.fixture()
def fake_graph(fresh_db):
    from app import integrations, sharepoint
    fake = FakeGraph()
    sharepoint.TRANSPORT = httpx.MockTransport(fake.handler)
    sharepoint._TOKEN.update(value="")
    sharepoint._SITES.clear()
    integrations.save({"graph_tenant_id": "tid", "graph_client_id": "cid", "graph_client_secret": "sec",
                       "sharepoint_site_url": "https://vendettacd.sharepoint.com/sites/Delivery",
                       "sharepoint_folder": "Engagements"}, "test")
    yield fake
    sharepoint.TRANSPORT = None


# ---------------------------------------------------------------- MCP helpers
def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"


def connect_claude(client, email: str) -> dict:
    """Run the whole connector flow as `email`: register, sign in, consent, token."""
    reg = client.post("/oauth/register", json={"client_name": "Claude", "redirect_uris": [CLAUDE_CB]})
    assert reg.status_code == 201, reg.text
    cid = reg.json()["client_id"]
    verifier, challenge = pkce()
    as_user(client, email)
    params = {"response_type": "code", "client_id": cid, "redirect_uri": CLAUDE_CB, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "st8", "resource": "https://pm.test.example/mcp"}
    page = client.get("/oauth/authorize", params=params)
    assert page.status_code == 200 and "Allow" in page.text
    csrf = page.text.split('name="csrf" value="')[1].split('"')[0]
    form = {"csrf": csrf, "decision": "approve", "client_id": cid, "redirect_uri": CLAUDE_CB,
            "code_challenge": challenge, "state": "st8", "scope": "", "resource": params["resource"]}
    r = client.post("/oauth/authorize", data=form, follow_redirects=False)
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    q = parse_qs(loc.query)
    assert q["state"] == ["st8"]
    tok = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                            "redirect_uri": CLAUDE_CB, "client_id": cid, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    client.cookies.clear()
    return {**tok.json(), "client_id": cid}


class Mcp:
    def __init__(self, client, token: str):
        self.client, self.token, self.n = client, token, 0

    def rpc(self, method: str, params: dict | None = None):
        self.n += 1
        r = self.client.post("/mcp", json={"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}},
                             headers={"Authorization": f"Bearer {self.token}"})
        return r

    def call(self, _tool: str, **args) -> dict:
        r = self.rpc("tools/call", {"name": _tool, "arguments": args})
        assert r.status_code == 200, r.text
        return r.json()["result"]

    def ok(self, _tool: str, **args) -> dict:
        res = self.call(_tool, **args)
        assert not res.get("isError"), res["content"][0]["text"]
        return res["structuredContent"]
