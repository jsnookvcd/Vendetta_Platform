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
    """Microsoft Graph for groups, sites, drives, Teams, list items and mail."""

    def __init__(self, site_ready_after: int = 0):
        self.users = {"pm@vendettacd.io": "u-pm", "dan@vendettacd.io": "u-dan", "kenedi@vendettacd.io": "u-ken",
                      "jordan@vendettacd.io": "u-jordan"}
        self.groups: dict[str, dict] = {}
        self.members: dict[str, set] = {}
        self.site_calls = 0
        self.site_ready_after = site_ready_after
        self.folders: set[str] = set()
        self.teams: set[str] = set()
        self.tabs: list[dict] = []
        self.installed: list[str] = []
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

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "login.microsoftonline.com" in url:
            return httpx.Response(200, json={"access_token": "graph-token", "expires_in": 3600})
        assert request.headers.get("authorization") == "Bearer graph-token"
        p = unquote(request.url.path).replace("/v1.0/", "/", 1)
        m = request.method
        self.calls.append(f"{m} {p}")
        body = json.loads(request.content) if request.content else {}
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
        if p == "/groups" and m == "GET":
            field, val = self._filter(request)
            rows = [g for g in self.groups.values() if str(g.get(field, "")).lower() == (val or "").lower()]
            return httpx.Response(200, json={"value": rows})
        if p == "/groups" and m == "POST":
            gid = f"g-{len(self.groups) + 1}"
            g = {"id": gid, "displayName": body["displayName"], "mailNickname": body["mailNickname"],
                 "mail": f"{body['mailNickname']}@vendettacd.io"}
            self.groups[gid] = g
            self.members[gid] = {u.rsplit("/", 1)[1] for u in body.get("members@odata.bind", [])}
            self.owners = body.get("owners@odata.bind", [])
            return httpx.Response(201, json=g)
        if p.endswith("/members") and m == "GET":
            gid = p.split("/")[2]
            return httpx.Response(200, json={"value": [{"id": i} for i in self.members.get(gid, set())]})
        if p.endswith("/members/$ref"):
            gid = p.split("/")[2]
            self.members[gid].add(body["@odata.id"].rsplit("/", 1)[1])
            return httpx.Response(204)
        if p.endswith("/sites/root"):
            self.site_calls += 1
            if self.site_calls <= self.site_ready_after:
                return httpx.Response(404)
            gid = p.split("/")[2]
            nick = self.groups[gid]["mailNickname"]
            return httpx.Response(200, json={"id": f"site-{gid}",
                                             "webUrl": f"https://vendettacd.sharepoint.com/sites/{nick}"})
        if p.startswith("/sites/") and "/drive/root" in p and m == "POST":
            parent = p.split("/drive/root")[1]
            parent = parent.split(":/")[1].split(":")[0] if parent.startswith(":") else ""
            full = f"{parent}/{body['name']}".strip("/")
            if full in self.folders:
                return httpx.Response(409)
            self.folders.add(full)
            return httpx.Response(201, json={"id": full})
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
        if p.startswith("/teams/"):
            tid = p.split("/")[2]
            if p == f"/teams/{tid}":
                return (httpx.Response(200, json={"id": tid, "webUrl": f"https://teams.example/{tid}"})
                        if tid in self.teams else httpx.Response(404))
            if p.endswith("/primaryChannel"):
                return httpx.Response(200, json={"id": f"19:{tid}@thread.tacv2", "webUrl": "https://teams.example/ch"})
            if p.endswith("/tabs") and m == "GET":
                return httpx.Response(200, json={"value": [{"displayName": t["displayName"]} for t in self.tabs
                                                           if t["team"] == tid]})
            if p.endswith("/tabs") and m == "POST":
                self.tabs.append({"team": tid, **body})
                return httpx.Response(201, json={"id": "tab"})
            if p.endswith("/installedApps"):
                self.installed.append(body["teamsApp@odata.bind"])
                return httpx.Response(201, json={})
        if p.startswith("/groups/") and p.endswith("/team") and m == "PUT":
            self.teams.add(p.split("/")[2])
            return httpx.Response(201, json={})
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
                                                       "ir_always_members", "group_owners", "max_attempts")}
    saved_s = (settings.platform_hub_url, settings.public_url, alert_settings.teams_webhook_url)
    kickoff_settings.vtime_site_url = "https://vendettacd.sharepoint.com/sites/VendettaTime"
    kickoff_settings.vtime_teams_app_id = "app-vtime"
    kickoff_settings.vtime_tab_content_url = "https://apps.powerapps.com/play/x?teamId={teamId}&channelId={channelId}"
    kickoff_settings.ir_always_members = "kenedi@vendettacd.io"
    kickoff_settings.group_owners = "jordan@vendettacd.io"
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
              "m365_group", "m365_site", "m365_team", "teams_tabs", "vendetta_time", "client_email", "announce"):
        assert st[k] == "ok", (k, out["steps"])
    assert st["mailbox_external"] == "manual"
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

    # Microsoft 365: IR naming convention, owners and members, folders, team, tabs
    g = next(iter(ms.groups.values()))
    assert g["displayName"] == "Incident Response-Atlantic Credit Union"
    assert g["mailNickname"] == code.lower()
    assert ms.members[g["id"]] >= {"u-pm", "u-dan", "u-ken", "u-jordan"}
    assert {"Evidence", "Evidence/Client Uploads", "Reports", "Meeting Notes"} <= ms.folders
    assert {t["displayName"] for t in ms.tabs} == {"Engagement board", "Vendetta Time"}
    board = next(t for t in ms.tabs if t["displayName"] == "Engagement board")
    assert board["configuration"]["contentUrl"] == f"https://pm.test.example/engagements/{out['engagement_id']}"
    vt = next(t for t in ms.tabs if t["displayName"] == "Vendetta Time")
    assert f"teamId={g['id']}" in vt["configuration"]["contentUrl"]

    # Vendetta Time rows link the Harvest project and lock the channel tab to the project
    row = ms.lists["Projects"][0]["fields"]
    assert row["ProjectCode"] == code and row["HarvestProjectId"] == "600"
    assert row["ProjectManagerLookupId"] == "14" and row["Practice"] == "Incident Response"
    tab = ms.lists["TabContexts"][0]["fields"]
    assert tab["ContextKey"] == f"channel|{g['id']}|19:{g['id']}@thread.tacv2" and tab["ProjectId"] == 1

    # Client email draft in the PM's mailbox, CC the case mailbox; delivery post
    mailbox, draft = ms.drafts[0]
    assert mailbox == "pm@vendettacd.io"
    assert draft["toRecipients"][0]["emailAddress"]["address"] == "cio@atlanticcu.example"
    assert draft["ccRecipients"][0]["emailAddress"]["address"] == g["mail"]
    assert "\u2014" not in draft["body"]["content"] and "\u2013" not in draft["body"]["content"]
    assert hub.webhook and code in json.dumps(hub.webhook[0])

    # The engagement now points at the new site, Harvest project and case
    from app.db import Engagement, SessionLocal
    db = SessionLocal()
    e = db.get(Engagement, out["engagement_id"])
    assert e.harvest_project_id == "600" and e.platform_ref == "VCD-IR-2026-801"
    assert e.sharepoint_site_url.endswith(code.lower()) and e.sharepoint_folder == "Meeting Notes"
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
    projects_before, groups_before = len(hv.created_projects), len(ms.groups)
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
    assert len(hv.created_projects) == projects_before and len(ms.groups) == groups_before
    assert ms.lists["Projects"][0]["fields"]["ProjectManagerLookupId"] == "21"


def test_proserv_fixed_fee_existing_client_and_name_clash(world):
    ms, hv = world["graph"], world["harvest"]
    ms.groups["g-old"] = {"id": "g-old", "displayName": "Professional Services-IFB", "mailNickname": "old",
                          "mail": "old@vendettacd.io"}
    out = _start({"practice": "proserv", "name": "vCISO onboarding", "client": "ifb", "pm_email": "pm@vendettacd.io",
                  "billing_type": "fixed_fee", "fee": "12500", "budget_hours": "60", "template": "vciso-onboarding"})
    assert out["status"] == "done", out["steps"]
    st = _status(out)
    assert st["platform"] == "skipped" and st["mailbox_external"] == "skipped"
    assert len(hv.clients) == 1  # matched IFB case-insensitively
    proj = hv.created_projects[0]
    assert proj["is_fixed_fee"] is True and proj["fee"] == 12500.0 and proj["bill_by"] == "People"
    names = {t["task"]["name"] for t in hv.tasks[600]}
    assert "Consulting" in names
    g = [x for x in ms.groups.values() if x["id"] != "g-old"][0]
    assert g["displayName"] == f"Professional Services-IFB {out['engagement']}"
    assert "Contracts" in ms.folders and "Evidence" not in ms.folders
    assert "kenedi" not in json.dumps(sorted(ms.members[g["id"]]))  # IR-only always-member


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
    assert st["m365_group"] == "skipped" and st["vendetta_time"] == "skipped" and st["harvest_client"] == "skipped"
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
    assert view.status_code == 200 and "Done" in view.text and "Set-UnifiedGroup" in view.text
    kid = r.headers["location"].rsplit("/", 1)[1]
    done = c.post(f"/kickoff/{kid}/steps/mailbox_external/done", follow_redirects=False)
    assert done.status_code == 303
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
    m.ok("retry_kickoff", kickoff=out["id"], step="mailbox_external", mark_done=True)
    err = m.call("kickoff_engagement", practice="ir", name="X", client="Y", billing_type="fixed_fee")
    assert err["isError"] and "fee" in err["content"][0]["text"]
