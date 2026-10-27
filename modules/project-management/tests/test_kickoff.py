"""Project kickoff: one request stands an engagement up across the module, the IR hub,
Harvest, Microsoft 365 (group, site, folders, Team, tabs), Vendetta Time, the client
email draft and the delivery channel. Harvest, Graph, the hub and the Teams webhook
are in-memory fakes behind httpx.MockTransport."""
import json
from urllib.parse import unquote

import httpx
import pytest

from conftest import FakeHarvest, Mcp, add_user, as_user, connect_claude


# ---------------------------------------------------------------- fakes
class KickoffHarvest(FakeHarvest):
    def __init__(self):
        super().__init__()
        self.clients = [{"id": 77, "name": "IFB", "is_active": True}]
        self.catalog = [{"id": 901, "name": "Forensic Analysis"}, {"id": 902, "name": "Project Management"},
                        {"id": 904, "name": "Incident Response"}, {"id": 905, "name": "Reporting"},
                        {"id": 906, "name": "Internal (Non-billable)"}, {"id": 903, "name": "Advisory"},
                        {"id": 907, "name": "Consulting"}]
        self.assignments: dict[int, list[dict]] = {}
        self.created_projects: list[dict] = []

    def handler(self, request):
        path = request.url.path.replace("/v2/", "", 1).strip("/")
        q = dict(request.url.params)
        m = request.method
        if path == "clients" and m == "GET":
            self.requests.append(request)
            return httpx.Response(200, json={"clients": self.clients, "links": {"next": None}})
        if path == "clients" and m == "POST":
            self.requests.append(request)
            body = json.loads(request.content)
            c = {"id": 80 + len(self.clients), "name": body["name"], "is_active": True}
            self.clients.append(c)
            return httpx.Response(201, json=c)
        if path == "projects" and m == "GET" and "client_id" in q:
            self.requests.append(request)
            rows = [p for p in self.projects if str((p.get("client") or {}).get("id")) == q["client_id"]]
            return httpx.Response(200, json={"projects": rows, "links": {"next": None}})
        if path == "projects" and m == "POST":
            self.requests.append(request)
            body = json.loads(request.content)
            pid = 600 + len(self.created_projects)
            client = next(c for c in self.clients if c["id"] == body["client_id"])
            p = {"id": pid, "name": body["name"], "code": body["code"], "client": {"id": client["id"],
                                                                                   "name": client["name"]}}
            self.created_projects.append(body)
            self.projects.append(p)
            self.tasks[pid] = []
            return httpx.Response(201, json=p)
        if path == "tasks":
            self.requests.append(request)
            return httpx.Response(200, json={"tasks": self.catalog, "links": {"next": None}})
        if path.endswith("task_assignments") and m == "POST":
            self.requests.append(request)
            pid = int(path.split("/")[1])
            body = json.loads(request.content)
            t = next(x for x in self.catalog if x["id"] == body["task_id"])
            self.tasks.setdefault(pid, []).append({"task": t, "billable": body["billable"]})
            return httpx.Response(201, json={"id": 1})
        if path.endswith("user_assignments"):
            self.requests.append(request)
            pid = int(path.split("/")[1])
            if m == "GET":
                return httpx.Response(200, json={"user_assignments": self.assignments.get(pid, []),
                                                 "links": {"next": None}})
            body = json.loads(request.content)
            row = {"id": 3000 + len(self.assignments.get(pid, [])), "user": {"id": body["user_id"]},
                   "is_project_manager": body["is_project_manager"]}
            self.assignments.setdefault(pid, []).append(row)
            return httpx.Response(201, json=row)
        return super().handler(request)


class FakeM365:
    """Microsoft Graph for practice teams, private channels and their files, mail
    folders and rules, Vendetta Time list items and mail drafts."""

    def __init__(self, site_ready_after: int = 0):
        self.users = {"pm@vendettacd.io": "u-pm", "dan@vendettacd.io": "u-dan", "kenedi@vendettacd.io": "u-ken",
                      "jordan@vendettacd.io": "u-jordan"}
        self.teams = {"team-ir": "Vendetta Incident Response", "team-ps": "Vendetta Professional Services"}
        self.members: dict[str, set] = {"team-ir": {"u-jordan"}, "team-ps": {"u-jordan"}}
        self.channels: dict[str, list[dict]] = {"team-ir": [], "team-ps": []}
        self.channel_members: dict[str, dict[str, list[str]]] = {}
        self.layouts: dict[str, str] = {}
        self.files_calls = 0
        self.site_ready_after = site_ready_after
        self.folders: dict[str, set[str]] = {}
        self.tabs: list[dict] = []
        self.installed: list[tuple[str, str]] = []
        self.mail_folders: dict[str, list[dict]] = {}
        self.rules: dict[str, list[dict]] = {}
        self.lists: dict[str, list[dict]] = {"Projects": [], "TabContexts": [],
                                            "User Information List": [{"id": "14", "fields": {"EMail": "pm@vendettacd.io"}}]}
        self.drafts: list[tuple[str, dict]] = []
        self.calls: list[str] = []

    def _filter(self, request):
        f = unquote(request.url.params.get("$filter", ""))
        if " eq '" in f:
            field, val = f.split(" eq '", 1)
            return field.split("/")[-1].strip(), val.rstrip("'").replace("''", "'")
        return None, None

    def _channel(self, cid):
        for tid, rows in self.channels.items():
            for ch in rows:
                if ch["id"] == cid:
                    return tid, ch
        return None, None

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "login.microsoftonline.com" in url:
            return httpx.Response(200, json={"access_token": "graph-token", "expires_in": 3600})
        assert request.headers.get("authorization") == "Bearer graph-token"
        p = unquote(request.url.path).replace("/v1.0/", "/", 1)
        m = request.method
        self.calls.append(f"{m} {p}")
        body = json.loads(request.content) if request.content else {}

        # ------------------------------------------------ mail
        if p.startswith("/users/") and "/mailFolders/inbox/" in p:
            mbx = p.split("/")[2]
            if mbx not in ("ir@vendettacd.io", "ps@vendettacd.io"):
                return httpx.Response(404)
            if p.endswith("/childFolders"):
                rows = self.mail_folders.setdefault(mbx, [])
                if m == "GET":
                    _, val = self._filter(request)
                    return httpx.Response(200, json={"value": [r for r in rows if r["displayName"] == val]})
                f = {"id": f"mf-{len(rows) + 1}", "displayName": body["displayName"]}
                rows.append(f)
                return httpx.Response(201, json=f)
            if p.endswith("/messageRules"):
                rows = self.rules.setdefault(mbx, [])
                if m == "GET":
                    return httpx.Response(200, json={"value": rows})
                rows.append(body)
                return httpx.Response(201, json=body)
        if p.startswith("/users/") and p.endswith("/messages") and m == "POST":
            self.drafts.append((p.split("/")[2], body))
            return httpx.Response(201, json={"id": "msg-1", "webLink": "https://outlook.example/msg-1"})
        if p.startswith("/users/") and m == "GET":
            uid = self.users.get(p.split("/")[2].lower())
            return httpx.Response(200, json={"id": uid}) if uid else httpx.Response(404)
        if p == "/users":
            _, val = self._filter(request)
            uid = self.users.get((val or "").lower())
            return httpx.Response(200, json={"value": [{"id": uid}] if uid else []})

        # ------------------------------------------------ practice team membership
        if p.startswith("/groups/") and p.endswith("/members") and m == "GET":
            gid = p.split("/")[2]
            return httpx.Response(200, json={"value": [{"id": i} for i in self.members.get(gid, set())]})
        if p.startswith("/groups/") and p.endswith("/members/$ref"):
            gid = p.split("/")[2]
            self.members[gid].add(body["@odata.id"].rsplit("/", 1)[1])
            return httpx.Response(204)

        # ------------------------------------------------ files
        if p.startswith("/drives/"):
            parts = p.split("/")
            drive = parts[2]
            if len(parts) == 3 and m == "GET":
                return httpx.Response(200, json={"id": drive, "webUrl": f"https://vendettacd.sharepoint.com/sites/{drive}/Shared Documents"})
            if m == "POST" and p.endswith("/children"):
                rest = p.split("/items/", 1)[1][: -len("/children")]
                root, _, parent = rest.partition(":/")
                parent = parent.rstrip(":")
                full = f"{parent}/{body['name']}".strip("/")
                have = self.folders.setdefault(drive, set())
                if full in have:
                    return httpx.Response(409)
                have.add(full)
                return httpx.Response(201, json={"id": full})

        # ------------------------------------------------ Vendetta Time lists
        if p.startswith("/sites/vendettacd.sharepoint.com:"):
            return httpx.Response(200, json={"id": "site-vtime"})
        if p.startswith("/sites/") and "/lists/" in p:
            name = p.split("/lists/")[1].split("/")[0]
            rows = self.lists.setdefault(name, [])
            if p.endswith("/items") and m == "GET":
                field, val = self._filter(request)
                return httpx.Response(200, json={"value": [r for r in rows if str(r["fields"].get(field)) == val]})
            if p.endswith("/items") and m == "POST":
                row = {"id": str(len(rows) + 1), "fields": body["fields"]}
                rows.append(row)
                return httpx.Response(201, json=row)
            if p.endswith("/fields") and m == "PATCH":
                iid = p.split("/items/")[1].split("/")[0]
                next(r for r in rows if r["id"] == iid)["fields"].update(body)
                return httpx.Response(200, json=body)

        # ------------------------------------------------ Teams
        if p.startswith("/teams/"):
            parts = p.split("/")
            tid = parts[2]
            if tid not in self.teams:
                return httpx.Response(404)
            if len(parts) == 3:
                return httpx.Response(200, json={"id": tid, "displayName": self.teams[tid],
                                                 "webUrl": f"https://teams.example/{tid}"})
            if parts[3] == "installedApps":
                self.installed.append((tid, body["teamsApp@odata.bind"]))
                return httpx.Response(201, json={})
            if parts[3] == "channels" and len(parts) == 4:
                rows = self.channels[tid]
                if m == "GET":
                    field, val = self._filter(request)
                    out = [c for c in rows if c["displayName"] == val] if field else rows
                    return httpx.Response(200, json={"value": out})
                cid = f"19:{tid}-{len(rows) + 1}@thread.tacv2"
                ch = {"id": cid, "displayName": body["displayName"], "membershipType": body.get("membershipType", "standard"),
                      "webUrl": f"https://teams.example/{tid}/{len(rows) + 1}"}
                rows.append(ch)
                self.channel_members[cid] = {}
                for mem in body.get("members", []):
                    uid = mem["user@odata.bind"].split("('")[1].rstrip("')")
                    self.channel_members[cid][uid] = mem["roles"]
                return httpx.Response(201, json=ch)
            cid = parts[4]
            _, ch = self._channel(cid)
            if ch is None:
                return httpx.Response(404)
            if len(parts) == 5 and m == "PATCH":
                self.layouts[cid] = body["layoutType"]
                return httpx.Response(204)
            sub = parts[5]
            if sub == "members":
                if m == "GET":
                    return httpx.Response(200, json={"value": [{"userId": u, "roles": r}
                                                               for u, r in self.channel_members[cid].items()]})
                uid = body["user@odata.bind"].split("('")[1].rstrip("')")
                if uid not in self.members[tid]:
                    return httpx.Response(400, json={"error": {"message": "not a member of the team"}})
                self.channel_members[cid][uid] = body["roles"]
                return httpx.Response(201, json={})
            if sub == "filesFolder":
                self.files_calls += 1
                if self.files_calls <= self.site_ready_after:
                    return httpx.Response(404)
                drive = "site-" + cid.split(":")[1].split("@")[0]
                return httpx.Response(200, json={"id": "root-" + drive, "name": ch["displayName"],
                                                 "webUrl": f"https://vendettacd.sharepoint.com/sites/{drive}/Shared Documents/{ch['displayName']}",
                                                 "parentReference": {"driveId": drive}})
            if sub == "tabs":
                if m == "GET":
                    return httpx.Response(200, json={"value": [{"displayName": t["displayName"]} for t in self.tabs
                                                               if t["channel"] == cid]})
                self.tabs.append({"team": tid, "channel": cid, **body})
                return httpx.Response(201, json={"id": "tab"})
        return httpx.Response(404)


class Hub:
    def __init__(self):
        self.cases: list[dict] = []
        self.milestones: list[tuple[str, dict]] = []
        self.webhook: list[dict] = []

    def handler(self, request):
        body = json.loads(request.content) if request.content else {}
        if request.url.path == "/api/ir-cases":
            self.cases.append(body)
            return httpx.Response(200, json={"case_id": f"VCD-IR-2026-{800 + len(self.cases)}", "linked": False})
        if request.url.path.endswith("/milestones"):
            self.milestones.append((request.url.path, body))
            return httpx.Response(200, json={"ok": True})
        if request.url.host == "webhook.example":
            self.webhook.append(body)
            return httpx.Response(200)
        return httpx.Response(404)


@pytest.fixture()
def world(fresh_db):
    from app import alerts, harvest, integrations, kickoff, m365, milestones, sharepoint
    from app.config import alert_settings, kickoff_settings, settings
    from app import service, templates_lib
    from app.db import SessionLocal
    db = SessionLocal()
    service.ensure_practice_boards(db)
    templates_lib.seed(db)
    db.commit()
    db.close()
    hv, ms, hub = KickoffHarvest(), FakeM365(), Hub()
    harvest.TRANSPORT = httpx.MockTransport(hv.handler)
    harvest._USERS.update(at=0.0, by_email={})
    sharepoint.TRANSPORT = httpx.MockTransport(lambda r: ms.handler(r))
    sharepoint._TOKEN.update(value="")
    sharepoint._SITES.clear()
    milestones.TRANSPORT = alerts.TRANSPORT = httpx.MockTransport(hub.handler)
    integrations.save({"harvest_account_id": "acct-1", "harvest_token": "hv-token", "graph_tenant_id": "tid",
                       "graph_client_id": "cid", "graph_client_secret": "sec"}, "test")
    saved = {k: getattr(kickoff_settings, k) for k in ("vtime_site_url", "vtime_teams_app_id", "vtime_tab_content_url",
                                                       "ir_always_members", "channel_owners", "max_attempts",
                                                       "ir_team_id", "proserv_team_id", "ir_mailbox", "proserv_mailbox")}
    saved_s = (settings.platform_hub_url, settings.public_url, alert_settings.teams_webhook_url)
    kickoff_settings.vtime_site_url = "https://vendettacd.sharepoint.com/sites/VendettaTime"
    kickoff_settings.vtime_teams_app_id = "app-vtime"
    kickoff_settings.vtime_tab_content_url = "https://apps.powerapps.com/play/x?teamId={teamId}&channelId={channelId}"
    kickoff_settings.ir_always_members = "kenedi@vendettacd.io"
    kickoff_settings.channel_owners = "jordan@vendettacd.io"
    kickoff_settings.ir_team_id, kickoff_settings.proserv_team_id = "team-ir", "team-ps"
    kickoff_settings.ir_mailbox, kickoff_settings.proserv_mailbox = "ir@vendettacd.io", "ps@vendettacd.io"
    settings.platform_hub_url = "http://ir-hub"
    alert_settings.teams_webhook_url = "https://webhook.example/delivery"
    yield {"harvest": hv, "graph": ms, "hub": hub, "kickoff": kickoff}
    for k, v in saved.items():
        setattr(kickoff_settings, k, v)
    settings.platform_hub_url, settings.public_url, alert_settings.teams_webhook_url = saved_s
    harvest.TRANSPORT = sharepoint.TRANSPORT = milestones.TRANSPORT = alerts.TRANSPORT = None
    _ = m365


IR_REQUEST = {"practice": "ir", "name": "Ransomware response", "client": "Atlantic Credit Union",
              "template": "ransomware", "pm_email": "pm@vendettacd.io", "lead_email": "dan@vendettacd.io",
              "team": "ghost@vendettacd.io:analyst", "budget_hours": "120", "billing_type": "hourly",
              "hourly_rate": "350", "starts_on": "2026-10-22", "client_contacts": "cio@atlanticcu.example",
              "severity": "critical"}


def _start(raw, actor="pm@vendettacd.io"):
    from app import kickoff
    from app.db import SessionLocal
    db = SessionLocal()
    k = kickoff.start(db, actor, raw)
    db.commit()
    kid = k.id
    db.close()
    kickoff.run(kid)
    db = SessionLocal()
    k = kickoff.find(db, kid)
    out = kickoff.kickoff_dict(db, k)
    db.close()
    return out


def _status(out):
    return {s["key"]: s["status"] for s in out["steps"]}


# ---------------------------------------------------------------- tests
def test_full_ir_kickoff(world):
    hv, ms, hub = world["harvest"], world["graph"], world["hub"]
    out = _start(IR_REQUEST)
    st = _status(out)
    assert out["status"] == "done", out["steps"]
    for k in ("engagement", "platform", "harvest_client", "harvest_project", "harvest_tasks", "harvest_team",
              "m365_team", "m365_channel", "m365_site", "mailbox", "teams_tabs", "time_channel", "vendetta_time",
              "client_email", "announce"):
        assert st[k] == "ok", (k, out["steps"])
    assert st["ticket"] == "skipped"

    # Engagement, template and platform case
    code = out["engagement"]
    assert code.startswith("VCD-IR-")
    assert hub.cases[0]["severity"] == "critical" and hub.cases[0]["source_module"] == "project-management"
    assert out["links"]["platform_ref"] == "VCD-IR-2026-801"
    assert hub.milestones and hub.milestones[0][0] == "/api/ir-cases/VCD-IR-2026-801/milestones"

    # Harvest: new client, project with budget and rate, practice tasks, team with PM as manager
    assert any(c["name"] == "Atlantic Credit Union" for c in hv.clients)
    proj = hv.created_projects[0]
    assert proj["code"] == code and proj["budget"] == 120.0 and proj["hourly_rate"] == 350.0
    assert proj["bill_by"] == "Project" and proj["is_fixed_fee"] is False
    names = {t["task"]["name"]: t["billable"] for t in hv.tasks[600]}
    assert names["Incident Response"] is True and names["Internal (Non-billable)"] is False
    assigned = {a["user"]["id"]: a["is_project_manager"] for a in hv.assignments[600]}
    assert assigned == {11: True, 12: False}
    team_step = next(s for s in out["steps"] if s["key"] == "harvest_team")
    assert "ghost@vendettacd.io" in team_step["warning"]

    # Microsoft 365: everyone joins the practice team; the engagement is a private
    # channel in it, PM and Jordan as owners, the team (plus Kenedi on IR) as members
    assert ms.members["team-ir"] >= {"u-pm", "u-dan", "u-ken", "u-jordan"}
    assert ms.members["team-ps"] == {"u-jordan"}
    case = next(c for c in ms.channels["team-ir"] if c["membershipType"] == "private")
    assert case["displayName"] == f"{code} Atlantic Credit Union"
    roles = ms.channel_members[case["id"]]
    assert roles["u-pm"] == ["owner"] and roles["u-jordan"] == ["owner"]
    assert roles["u-dan"] == [] and roles["u-ken"] == []
    assert ms.layouts[case["id"]] == "chat"
    drive = "site-" + case["id"].split(":")[1].split("@")[0]
    assert {"Evidence", "Evidence/Client Uploads", "Reports", "Meeting Notes"} <= ms.folders[drive]

    # Engagement email: plus address on the IR mailbox, its own folder and rule
    addr = f"ir+{code.lower()}@vendettacd.io"
    assert out["links"]["mailbox"] == addr
    assert ms.mail_folders["ir@vendettacd.io"][0]["displayName"] == case["displayName"]
    rule = ms.rules["ir@vendettacd.io"][0]
    assert rule["conditions"]["headerContains"] == [addr] and rule["actions"]["moveToFolder"] == "mf-1"

    # Tabs: board and locked Vendetta Time on the case channel; Log Time on Time Entry
    case_tabs = {t["displayName"]: t for t in ms.tabs if t["channel"] == case["id"]}
    assert set(case_tabs) == {"Engagement board", "Vendetta Time"}
    assert case_tabs["Engagement board"]["configuration"]["contentUrl"] == \
        f"https://pm.test.example/engagements/{out['engagement_id']}"
    assert f"channelId={case['id']}" in case_tabs["Vendetta Time"]["configuration"]["contentUrl"]
    tc = next(c for c in ms.channels["team-ir"] if c["displayName"] == "Time Entry")
    assert tc["membershipType"] == "standard"
    assert [t["displayName"] for t in ms.tabs if t["channel"] == tc["id"]] == ["Log Time"]

    # Vendetta Time rows link the Harvest project and lock the case channel's tab only
    row = ms.lists["Projects"][0]["fields"]
    assert row["ProjectCode"] == code and row["HarvestProjectId"] == "600"
    assert row["ProjectManagerLookupId"] == "14" and row["Practice"] == "Incident Response"
    assert len(ms.lists["TabContexts"]) == 1
    tab = ms.lists["TabContexts"][0]["fields"]
    assert tab["ContextKey"] == f"channel|team-ir|{case['id']}" and tab["ProjectId"] == 1

    # Client email draft in the PM's mailbox, CC the case mailbox; delivery post
    mailbox, draft = ms.drafts[0]
    assert mailbox == "pm@vendettacd.io"
    assert draft["toRecipients"][0]["emailAddress"]["address"] == "cio@atlanticcu.example"
    assert draft["ccRecipients"][0]["emailAddress"]["address"] == addr
    assert "\u2014" not in draft["body"]["content"] and "\u2013" not in draft["body"]["content"]
    assert hub.webhook and code in json.dumps(hub.webhook[0])

    # The engagement now points at the new site, Harvest project and case
    from app.db import Engagement, SessionLocal
    db = SessionLocal()
    e = db.get(Engagement, out["engagement_id"])
    assert e.harvest_project_id == "600" and e.platform_ref == "VCD-IR-2026-801"
    assert e.sharepoint_site_url == f"https://vendettacd.sharepoint.com/sites/{drive}"
    assert e.sharepoint_folder == f"{case['displayName']}/Meeting Notes"
    assert e.engagement_type == "ransomware"
    db.close()


def test_waits_for_site_then_finishes(world):
    world["graph"].site_ready_after = 2
    out = _start(dict(IR_REQUEST, client_contacts=""))
    assert out["status"] == "waiting"
    assert _status(out)["m365_site"] == "waiting"
    assert _status(out)["vendetta_time"] == "ok"  # does not need the site
    assert _status(out)["teams_tabs"] == "pending"
    assert _status(out)["announce"] == "pending"

    from app import kickoff
    from app.db import Kickoff, SessionLocal
    db = SessionLocal()
    db.query(Kickoff).update({"next_run_at": None})
    db.commit()
    db.close()
    kickoff.run(out["id"])
    kickoff.run(out["id"])  # a second worker pass is harmless
    db = SessionLocal()
    k = kickoff.find(db, out["id"])
    assert k.status in ("waiting", "done")
    if k.status == "waiting":
        k.next_run_at = None
        db.commit()
        kickoff.run(out["id"])
        db.refresh(k)
    assert k.status == "done", k.steps
    assert len(world["hub"].webhook) == 1
    db.close()


def test_failure_then_retry_does_not_repeat_work(world):
    ms, hv = world["graph"], world["harvest"]
    ms.lists["User Information List"] = []  # PM never opened Vendetta Time
    out = _start(IR_REQUEST)
    assert out["status"] == "attention"
    assert _status(out)["vendetta_time"] == "failed"
    assert "Vendetta Time site" in next(s for s in out["steps"] if s["key"] == "vendetta_time")["detail"]
    assert _status(out)["announce"] == "ok"  # posts even when one step failed

    ms.lists["User Information List"] = [{"id": "21", "fields": {"EMail": "pm@vendettacd.io"}}]
    projects_before, channels_before = len(hv.created_projects), len(ms.channels["team-ir"])
    from app import kickoff
    from app.db import SessionLocal
    db = SessionLocal()
    k = kickoff.find(db, out["id"])
    kickoff.retry(db, "pm@vendettacd.io", k)
    db.commit()
    db.close()
    kickoff.run(out["id"])
    db = SessionLocal()
    res = kickoff.kickoff_dict(db, kickoff.find(db, out["id"]))
    db.close()
    assert res["status"] == "done", res["steps"]
    assert len(hv.created_projects) == projects_before and len(ms.channels["team-ir"]) == channels_before
    assert len(ms.rules["ir@vendettacd.io"]) == 1 and len(ms.tabs) == 3  # nothing made twice
    assert ms.lists["Projects"][0]["fields"]["ProjectManagerLookupId"] == "21"


def test_proserv_fixed_fee_existing_client_and_channel_name(world):
    ms, hv = world["graph"], world["harvest"]
    out = _start({"practice": "proserv", "name": "vCISO onboarding", "client": "ifb", "pm_email": "pm@vendettacd.io",
                  "codename": "Harbor & Bay / Risk Program: Phase One, Northeast Region",
                  "billing_type": "fixed_fee", "fee": "12500", "budget_hours": "60", "template": "vciso-onboarding"})
    assert out["status"] == "done", out["steps"]
    st = _status(out)
    assert st["platform"] == "skipped"
    assert len(hv.clients) == 1  # matched IFB case-insensitively
    proj = hv.created_projects[0]
    assert proj["is_fixed_fee"] is True and proj["fee"] == 12500.0 and proj["bill_by"] == "People"
    names = {t["task"]["name"] for t in hv.tasks[600]}
    assert "Consulting" in names
    # ProServ goes to its own practice team and mailbox; the IR team is untouched
    assert ms.channels["team-ir"] == []
    case = next(c for c in ms.channels["team-ps"] if c["membershipType"] == "private")
    name = case["displayName"]
    assert name.startswith(out["engagement"]) and len(name) <= 50
    assert not any(ch in name for ch in "&/:,")
    assert "u-ken" not in ms.channel_members[case["id"]]  # IR-only always-member
    drive = "site-" + case["id"].split(":")[1].split("@")[0]
    assert "Contracts" in ms.folders[drive] and "Evidence" not in ms.folders[drive]
    assert out["links"]["mailbox"] == f"ps+{out['engagement'].lower()}@vendettacd.io"


def test_channel_limit_warning(world):
    ms = world["graph"]
    ms.channels["team-ir"] = [{"id": f"19:old-{i}@thread.tacv2", "displayName": f"Old {i}", "membershipType": "private",
                               "webUrl": ""} for i in range(905)]
    out = _start(dict(IR_REQUEST, client_contacts=""))
    assert out["status"] == "done", out["steps"]
    team_step = next(s for s in out["steps"] if s["key"] == "m365_team")
    assert "905 of 1000 channels" in team_step["warning"]


def test_channel_name_rules():
    from app import m365
    assert m365.channel_name("VCD-IR-2026-014", "Atlantic Credit Union") == "VCD-IR-2026-014 Atlantic Credit Union"
    n = m365.channel_name("VCD-IR-2026-014", 'A&B "Bank" #1 / Main: Branch? <HQ> ... and a very long tail here')
    assert len(n) <= 50 and not any(ch in n for ch in '&"#/:?<>') and ".." not in n
    assert m365.plus_address("IR@vendettacd.io", "vcd-ir-2026-014") == "ir+vcd-ir-2026-014@vendettacd.io"
    assert m365.plus_address("ir+old@vendettacd.io", "x") == "ir+x@vendettacd.io"


def test_validation_and_options(world):
    from app import kickoff
    from app.db import SessionLocal
    from app.service import ServiceError
    db = SessionLocal()
    with pytest.raises(ServiceError, match="client"):
        kickoff.start(db, "pm@vendettacd.io", {"practice": "ir", "name": "X"})
    with pytest.raises(ServiceError, match="fee"):
        kickoff.start(db, "pm@vendettacd.io", {"practice": "ir", "name": "X", "client": "Y", "billing_type": "fixed fee"})
    with pytest.raises(ServiceError, match="email"):
        kickoff.start(db, "pm@vendettacd.io", {"practice": "ir", "name": "X", "client": "Y", "team": "not-an-email"})
    with pytest.raises(ServiceError, match="for Professional Services"):
        kickoff.start(db, "pm@vendettacd.io", {"practice": "ir", "name": "X", "client": "Y", "template": "tabletop"})
    db.close()
    out = _start({"practice": "ir", "name": "BEC", "client": "IFB", "pm_email": "pm@vendettacd.io",
                  "harvest_project_id": "501", "platform_ref": "VCD-IR-2026-445",
                  "options": {"m365": False, "vendetta_time": False, "announce": False}})
    st = _status(out)
    assert out["status"] == "done", out["steps"]
    assert st["m365_channel"] == "skipped" and st["mailbox"] == "skipped" and st["time_channel"] == "skipped"
    assert st["vendetta_time"] == "skipped" and st["harvest_client"] == "skipped"
    assert st["harvest_project"] == "ok" and not world["harvest"].created_projects
    assert not world["hub"].cases  # linked the existing case
    assert out["links"]["platform_ref"] == "VCD-IR-2026-445"


def test_web_wizard_and_viewer(world, client):
    add_user("pm@vendettacd.io", "analyst")
    add_user("viewer@vendettacd.io", "viewer")
    c = as_user(client, "pm@vendettacd.io")
    page = c.get("/kickoff")
    assert page.status_code == 200 and "Kick off" in page.text and "TICKETING NOT CHOSEN" in page.text
    bad = c.post("/kickoff", data={"practice": "ir", "name": "Only a name", "client": ""})
    assert bad.status_code == 200 and "Name the client" in bad.text and "Only a name" in bad.text
    form = {k: v for k, v in IR_REQUEST.items()}
    form.update({f"opt_{k}": "1" for k in ("platform", "harvest", "m365", "vendetta_time", "client_email", "announce")})
    r = c.post("/kickoff", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/kickoff/")
    view = c.get(r.headers["location"])
    assert view.status_code == 200 and "Done" in view.text and "ir+vcd-ir-" in view.text
    assert "Manual" not in view.text  # nothing left for a person to do in Exchange
    kid = r.headers["location"].rsplit("/", 1)[1]
    v = as_user(client, "viewer@vendettacd.io")
    assert v.post("/kickoff", data=form).status_code == 403
    assert v.get(f"/kickoff/{kid}").status_code == 200


def test_mcp_kickoff(world, client):
    add_user("pm@vendettacd.io", "analyst")
    tok = connect_claude(client, "pm@vendettacd.io")
    m = Mcp(client, tok["access_token"])
    names = {t["name"] for t in m.rpc("tools/list").json()["result"]["tools"]}
    assert {"kickoff_engagement", "get_kickoff", "retry_kickoff"} <= names
    out = m.ok("kickoff_engagement", practice="ir", name="BEC response", client="IFB", pm="me",
               lead="dan@vendettacd.io", team=[{"email": "kenedi@vendettacd.io", "role": "coordinator"}],
               budget_hours=40, template="bec", skip=["client_email"])
    assert out["status"] == "done", out["steps"]
    got = m.ok("get_kickoff", kickoff=out["engagement"])
    assert got["id"] == out["id"]
    again = m.ok("retry_kickoff", kickoff=out["id"], step="time_channel")
    assert again["status"] == "done"
    err = m.call("kickoff_engagement", practice="ir", name="X", client="Y", billing_type="fixed_fee")
    assert err["isError"] and "fee" in err["content"][0]["text"]
