"""Tests run against a real Postgres for the responder's own tables, with Slack, the
control plane, the IR hub and SABINE faked behind one httpx MockTransport. Point
SLACK_TEST_DATABASE_URL at a disposable database; tables are dropped and recreated.
Skipped if the database is unreachable."""
import json
import os
import sys
from urllib.parse import parse_qs

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
TEST_DB = os.environ.get("SLACK_TEST_DATABASE_URL", "postgresql+psycopg://slack:slack@localhost:5432/slack_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["SLACK_BOT_TOKEN"] = "xoxb-test"
os.environ["SLACK_SIGNING_SECRET"] = "shh-signing"
os.environ["SLACK_APP_TOKEN"] = ""
os.environ["SLACK_IR_CHANNEL"] = "C_IR"
os.environ["SLACK_SABINE_CHANNEL"] = "C_SAB"
os.environ["POLL_INTERVAL_SECONDS"] = "0"
os.environ["WARROOM_INVITE"] = "U_LEADER"
os.environ["MODULE_DIRECTORY"] = json.dumps({
    "incident-response": {"base_url": "http://ir.test", "token": "ir-token", "public_url": "https://ir.example"},
    "sabine": {"base_url": "http://sabine.test", "token": "sabine-token", "public_url": "https://sabine.example"},
    "platform": {"base_url": "http://platform.test", "token": "platform-token", "public_url": "https://platform.example"},
})

import bcrypt  # noqa: E402

os.environ["ADMIN_PASSWORD_HASH"] = bcrypt.hashpw(b"pw", bcrypt.gensalt(4)).decode()

PEOPLE = {
    "U_DAN": {"email": "dan@vendettacd.io", "name": "Dan Baker"},
    "U_JORDAN": {"email": "jordan@vendettacd.io", "name": "Jordan Snook"},
    "U_VIEW": {"email": "viewer@vendettacd.io", "name": "Vic Viewer"},
    "U_OUT": {"email": "eve@gmail.com", "name": "Eve Outsider"},
    "U_NOBODY": {"email": "nobody@vendettacd.io", "name": "Not Rostered"},
    "U_LEADER": {"email": "kenedi@vendettacd.io", "name": "Kenedi Crossley"},
}


def _db_up() -> bool:
    try:
        from sqlalchemy import create_engine, text

        with create_engine(TEST_DB).connect() as c:
            c.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


class World:
    """Everything the responder talks to, recording every call."""

    def __init__(self):
        self.slack_calls: list[tuple[str, dict]] = []
        self.responses: list[tuple[str, dict]] = []
        self.platform_calls: list[tuple[str, str, dict]] = []
        self.ir_calls: list[dict] = []
        self.sabine_calls: list[dict] = []
        self.ts = 1000
        self.roster = {
            "incident-response": [
                {"email": "dan@vendettacd.io", "role": "analyst", "name": "Dan Baker"},
                {"email": "jordan@vendettacd.io", "role": "admin", "name": "Jordan Snook"},
                {"email": "viewer@vendettacd.io", "role": "viewer", "name": "Vic Viewer"},
            ],
            "sabine": [
                {"email": "dan@vendettacd.io", "role": "analyst", "name": "Dan Baker"},
                {"email": "jordan@vendettacd.io", "role": "admin", "name": "Jordan Snook"},
                {"email": "viewer@vendettacd.io", "role": "viewer", "name": "Vic Viewer"},
            ],
        }
        self.governs = True
        self.clients = [{"id": "plat-rb", "name": "Riverbend Credit Union"}, {"id": "plat-hp", "name": "Harbor Point"},
                        {"id": "plat-rf", "name": "Riverfront Dental"}]
        self.cases: dict[str, dict] = {}
        self.seq = 780
        self.proposals: dict[str, dict] = {}
        self.history: dict[tuple[str, str], dict] = {}
        self.platform_up = True

    # ------------------------------------------------------------ helpers
    def slack(self, method: str) -> list[dict]:
        return [p for m, p in self.slack_calls if m == method]

    def ir(self, path_suffix: str) -> list[dict]:
        return [c for c in self.ir_calls if c["path"].endswith(path_suffix)]

    def add_case(self, client="Riverbend Credit Union", pid="plat-rb", severity="high", status="open", lead="",
                 origin="escalated"):
        self.seq += 1
        number = f"VCD-IR-2026-{self.seq}"
        cid = f"case{self.seq}"
        self.cases[number] = {
            "id": cid, "case_id": number, "number": number, "seq": self.seq, "title": f"[MDR] Ransomware on WS0{self.seq % 10}",
            "client": {"id": "hub-" + pid, "name": client, "platform_client_id": pid},
            "severity": severity, "status": status, "origin": origin, "source_module": "mdr" if origin == "escalated" else "",
            "lead": lead, "privileged": False, "opened_at": "2026-10-17T18:00:00+00:00", "closed_at": None,
            "last_update_at": "2026-10-17T18:00:00+00:00",
            "workstreams": [{"name": "Scoping and Containment", "status": "in_progress", "owner": "",
                             "cards": {"todo": 2, "in_progress": 1, "blocked": 0, "done": 1}}],
            "board": {}, "tasks": [{"id": "t1", "workstream": "Scoping and Containment", "title": "Isolate affected hosts",
                                    "status": "todo", "owner": "", "due_on": None}],
            "updates": [], "incident_type": "",
        }
        return self.cases[number]

    def _case(self, ref: str) -> dict | None:
        for c in self.cases.values():
            if c["number"].upper() == ref.upper() or c["id"] == ref:
                return c
        return None

    # ------------------------------------------------------------ the transport
    def handler(self, req: httpx.Request) -> httpx.Response:
        host = req.url.host
        if host == "slack.com":
            return self._slack(req)
        if host == "hooks.slack.com":
            self.responses.append((str(req.url), json.loads(req.content)))
            return httpx.Response(200, text="ok")
        if host == "platform.test":
            return self._platform(req)
        if host == "ir.test":
            return self._ir(req)
        if host == "sabine.test":
            return self._sabine(req)
        return httpx.Response(404)

    def _slack(self, req: httpx.Request) -> httpx.Response:
        method = req.url.path.rsplit("/", 1)[-1]
        if req.headers.get("content-type", "").startswith("application/json"):
            params = json.loads(req.content or b"{}")
        else:
            params = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
        self.slack_calls.append((method, params))
        ok = lambda **kw: httpx.Response(200, json={"ok": True, **kw})  # noqa: E731
        if method == "auth.test":
            return ok(team_id="T_VCD", user_id="U_BOT")
        if method == "users.info":
            p = PEOPLE.get(params.get("user"))
            if not p:
                return httpx.Response(200, json={"ok": False, "error": "user_not_found"})
            return ok(user={"id": params["user"], "name": p["name"].split()[0].lower(),
                            "profile": {"email": p["email"], "real_name": p["name"]}})
        if method == "users.lookupByEmail":
            uid = next((k for k, v in PEOPLE.items() if v["email"] == params.get("email")), "")
            return ok(user={"id": uid}) if uid else httpx.Response(200, json={"ok": False, "error": "users_not_found"})
        if method == "conversations.create":
            return ok(channel={"id": "G_ROOM" + str(len(self.slack("conversations.create"))), "name": params["name"]})
        if method in ("chat.postMessage", "chat.update"):
            self.ts += 1
            return ok(ts=params.get("ts") or f"{self.ts}.000100", channel=params.get("channel"))
        if method == "conversations.history":
            m = self.history.get((params.get("channel"), params.get("latest")))
            return ok(messages=[m] if m else [])
        if method == "conversations.replies":
            return ok(messages=[])
        if method == "chat.getPermalink":
            return ok(permalink=f"https://vcd.slack.com/archives/{params['channel']}/p{params['message_ts'].replace('.', '')}")
        if method == "conversations.info":
            return ok(channel={"id": params["channel"], "name": "general-ir", "is_member": True, "is_private": False})
        return ok()

    def _platform(self, req: httpx.Request) -> httpx.Response:
        self.platform_calls.append((req.method, req.url.path, dict(req.url.params)))
        if not self.platform_up:
            return httpx.Response(503)
        if req.headers.get("authorization") != "Bearer platform-token":
            return httpx.Response(401)
        if req.url.path == "/api/platform/staff":
            mod = req.url.params.get("module")
            return httpx.Response(200, json={"module": mod, "governs": self.governs, "staff": self.roster.get(mod, [])})
        if req.url.path == "/api/platform/clients":
            return httpx.Response(200, json={"module": "incident-response", "clients": self.clients})
        return httpx.Response(404)

    def _ir(self, req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else {}
        call = {"method": req.method, "path": req.url.path, "body": body, "params": dict(req.url.params),
                "actor": req.headers.get("x-vendetta-actor"), "person": req.headers.get("x-vendetta-on-behalf-of"),
                "auth": req.headers.get("authorization")}
        self.ir_calls.append(call)
        if call["auth"] != "Bearer ir-token":
            return httpx.Response(401, json={"detail": "bad token"})
        p = req.url.path
        if p == "/api/ir-cases" and req.method == "GET":
            return httpx.Response(200, json=[c for c in self.cases.values() if c["status"] != "closed"])
        if p == "/api/ir-cases/declare":
            client = next((c for c in self.clients if c["id"] == body.get("platform_client_id")), None)
            c = self.add_case(client=client["name"] if client else body.get("client", "?"),
                              pid=body.get("platform_client_id", ""), severity=body.get("severity", "high"), origin="declared")
            return httpx.Response(200, json={"case_id": c["number"], "id": c["id"], "link": f"https://ir.example/cases/{c['id']}"})
        if p == "/api/oncall/page":
            return httpx.Response(200, json={"sent": {"teams": "sent"}})
        parts = p.split("/")  # ['', 'api', 'ir-cases', ref, ...]
        if len(parts) >= 4 and parts[2] == "ir-cases":
            c = self._case(parts[3])
            if c is None:
                return httpx.Response(404, json={"detail": "no case"})
            tail = parts[4:] if len(parts) > 4 else []
            if not tail and req.method == "GET":
                return httpx.Response(200, json=c)
            if tail == ["updates"]:
                c["updates"].insert(0, {"at": "2026-10-17T18:05:00+00:00", "actor": f"{call['person']} via slack",
                                        "kind": "note", "note": body["note"], "workstream": body.get("workstream", ""),
                                        "internal_only": True})
                return httpx.Response(200, json={"ok": True, "case_id": c["number"], "update_id": "u1"})
            if tail == ["status"]:
                old = c["status"]
                c["status"] = body["status"]
                return httpx.Response(200, json={"ok": True, "case_id": c["number"], "from": old, "status": body["status"]})
            if tail == ["details"]:
                for k in ("severity", "lead"):
                    if k in body:
                        c[k] = body[k]
                return httpx.Response(200, json={"ok": True, "case_id": c["number"], "changes": ["x"]})
            if tail == ["tasks"]:
                t = {"id": f"t{len(c['tasks']) + 1}", "workstream": body["workstream"], "title": body["title"],
                     "status": "todo", "owner": body.get("owner", ""), "due_on": None}
                c["tasks"].append(t)
                return httpx.Response(200, json={"ok": True, "case_id": c["number"], "task": t})
            if len(tail) == 3 and tail[0] == "tasks" and tail[2] == "move":
                t = next(t for t in c["tasks"] if t["id"] == tail[1])
                t["status"] = body["status"]
                return httpx.Response(200, json={"ok": True, "case_id": c["number"], "moved": True, "task": t})
        return httpx.Response(404, json={"detail": "not found"})

    def _sabine(self, req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else {}
        call = {"method": req.method, "path": req.url.path, "body": body, "params": dict(req.url.params),
                "person": req.headers.get("x-vendetta-on-behalf-of")}
        self.sabine_calls.append(call)
        p = req.url.path
        if p == "/api/proposals":
            st = req.url.params.get("status")
            rows = list(self.proposals.values())
            return httpx.Response(200, json=rows if st == "all" else [r for r in rows if r["status"] == st])
        if p.endswith("/decide"):
            pid = p.split("/")[3]
            prop = self.proposals[pid]
            if prop["risk"] == "high":
                return httpx.Response(403, json={"detail": "a high-risk proposal is decided by a person in the console"})
            if prop["status"] != "pending":
                return httpx.Response(409, json={"ok": False, "proposal": prop})
            prop["status"] = "executed" if body["approve"] else "rejected"
            prop["decided_by"] = f"{call['person']} via slack"
            return httpx.Response(200, json={"ok": True, "proposal": prop, "result": {"ok": True}})
        if p == "/api/ask":
            return httpx.Response(200, json={"reply": "Two criticals open on Riverbend. Dan has the ransomware case.",
                                             "outcome": "", "proposal": None})
        return httpx.Response(404)

    def proposal(self, pid="p1", risk="medium", status="pending", title="Escalate the Riverbend critical"):
        self.proposals[pid] = {"id": pid, "action": "escalate_finding", "domain": "soc", "title": title,
                               "rationale": "Critical finding open 45 minutes with no case.", "facts": {"client": "Riverbend Credit Union"},
                               "target": {}, "confidence": 0.82, "risk": risk, "autonomy": "propose", "status": status,
                               "decided_by": "", "result": {}, "created_at": "2026-10-17T18:00:00+00:00"}
        return self.proposals[pid]


@pytest.fixture()
def world():
    if not _db_up():
        pytest.skip("test database not reachable")
    from sqlalchemy.orm import close_all_sessions

    from app import identity, reach, responder, slack
    from app.db import Base, engine, init_db

    close_all_sessions()
    engine.dispose()
    Base.metadata.drop_all(engine)
    init_db()
    w = World()
    t = httpx.MockTransport(w.handler)
    slack.set_transport(t)
    reach.set_transport(t)
    identity.reset_cache()
    responder.room_last.clear()
    responder.DEFER = lambda fn: fn()
    slack.IDENTITY.update(team_id="T_VCD", bot_user_id="U_BOT", checked=True, detail="ok")
    yield w
    close_all_sessions()
    engine.dispose()


@pytest.fixture()
def client(world):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as tc:
        yield tc


def cmd(text: str, user: str = "U_DAN", channel: str = "C_GENERAL") -> dict:
    return {"team_id": "T_VCD", "user_id": user, "channel_id": channel, "command": "/ir", "text": text,
            "response_url": "https://hooks.slack.com/commands/T/1/x", "trigger_id": "trig1"}
