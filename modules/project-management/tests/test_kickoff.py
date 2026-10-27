"""Engagement kickoff: one call opens the engagement in every system, a retry never
duplicates anything, the mailbox worker closes the loop, and missing integrations
are skipped with follow-ups for Claude."""
import json
import re
from urllib.parse import unquote

import httpx
import pytest

from conftest import FakeHarvest, Mcp, add_user, connect_claude


# ---------------------------------------------------------------- fakes
class KickoffHarvest(FakeHarvest):
    def __init__(self):
        super().__init__()
        self.clients = [{"id": 77, "name": "IFB"}]
        self.catalog = [{"id": 901, "name": "Forensic Analysis"}, {"id": 902, "name": "Project Management"},
                        {"id": 904, "name": "Incident Response"}, {"id": 905, "name": "Report Writing"},
                        {"id": 906, "name": "Consulting"}]
        self.user_assign: dict[int, list] = {}
        self.project_posts = 0

    def handler(self, request):
        path = request.url.path.replace("/v2/", "", 1).strip("/")
        if path == "clients" and request.method == "GET":
            return httpx.Response(200, json={"clients": self.clients, "links": {"next": None}})
        if path == "clients" and request.method == "POST":
            c = {"id": 70 + len(self.clients), **json.loads(request.content)}
            self.clients.append(c)
            return httpx.Response(201, json=c)
        if path == "tasks":
            return httpx.Response(200, json={"tasks": self.catalog, "links": {"next": None}})
        if path == "projects" and request.method == "POST":
            self.project_posts += 1
            body = json.loads(request.content)
            p = {"id": 600 + self.project_posts, "name": body["name"], "code": body["code"],
                 "client": {"id": body["client_id"]}, "budget": body.get("budget")}
            self.projects.append(p)
            self.tasks[p["id"]] = []
            return httpx.Response(201, json=p)
        m = re.match(r"projects/(\d+)/(task|user)_assignments$", path)
        if m:
            pid = int(m.group(1))
            if m.group(2) == "task":
                if request.method == "POST":
                    tid = json.loads(request.content)["task_id"]
                    t = next(x for x in self.catalog if x["id"] == tid)
                    self.tasks.setdefault(pid, []).append({"task": t, "billable": True})
                    return httpx.Response(201, json={})
                return httpx.Response(200, json={"task_assignments": self.tasks.get(pid, []), "links": {"next": None}})
            if request.method == "POST":
                uid = json.loads(request.content)["user_id"]
                self.user_assign.setdefault(pid, []).append({"user": {"id": uid}})
                return httpx.Response(201, json={})
            return httpx.Response(200, json={"user_assignments": self.user_assign.get(pid, []),
                                             "links": {"next": None}})
        return super().handler(request)


class FakeWorkspace:
    """Microsoft Graph for the M365 workspace: users, groups, teams, channels, tags, drives."""

    def __init__(self):
        self.groups: dict[str, dict] = {}
        self.team_puts = 0
        self.channels: dict[str, list] = {}
        self.channel_bodies: list[dict] = []
        self.tags: dict[str, list] = {}
        self.items: dict[str, dict] = {"lib/tools/crowdstrike-sensor": {"id": "src-cs"}}
        self.invites: list[dict] = []
        self.copies: list[dict] = []
        self.group_posts = 0
        self.reject_layout = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "login.microsoftonline.com" in url:
            return httpx.Response(200, json={"access_token": "graph-token", "expires_in": 3600})
        path = unquote(request.url.path.replace("/v1.0/", "", 1))
        body = json.loads(request.content) if request.content else {}
        if path.startswith("users/"):
            email = path.split("/")[1]
            if email.endswith("@vendettacd.io"):
                return httpx.Response(200, json={"id": "u-" + email.split("@")[0]})
            return httpx.Response(404)
        if path == "groups" and request.method == "GET":
            nick = request.url.params["$filter"].split("'")[1]
            return httpx.Response(200, json={"value": [g for g in self.groups.values() if g["mailNickname"] == nick]})
        if path == "groups" and request.method == "POST":
            self.group_posts += 1
            gid = f"g{self.group_posts}"
            self.groups[gid] = {"id": gid, "mailNickname": body["mailNickname"],
                                "mail": f"{body['mailNickname']}@vendettacd.io", "body": body}
            return httpx.Response(201, json=self.groups[gid])
        m = re.match(r"groups/(\w+)/team$", path)
        if m:
            self.team_puts += 1
            if self.team_puts == 1:
                return httpx.Response(404)  # not replicated yet
            return httpx.Response(201, json={"id": m.group(1), "webUrl": f"https://teams.example/{m.group(1)}"})
        m = re.match(r"teams/(\w+)/channels$", path)
        if m:
            chans = self.channels.setdefault(m.group(1), [{"id": "c0", "displayName": "General"}])
            if request.method == "GET":
                return httpx.Response(200, json={"value": chans})
            if self.reject_layout and "layoutType" in body:
                return httpx.Response(400, json={"error": {"message": "layoutType not supported"}})
            self.channel_bodies.append(body)
            ch = {"id": f"c{len(chans)}", "displayName": body["displayName"]}
            chans.append(ch)
            return httpx.Response(201, json=ch)
        if re.match(r"teams/\w+/channels/\w+/members$", path):
            return httpx.Response(201, json={})
        if path.endswith("/primaryChannel"):
            return httpx.Response(200, json={})
        m = re.match(r"teams/(\w+)/tags$", path)
        if m:
            tags = self.tags.setdefault(m.group(1), [])
            if request.method == "GET":
                return httpx.Response(200, json={"value": tags})
            t = {"id": f"t{len(tags)}", "displayName": body["displayName"], "members": body["members"]}
            tags.append(t)
            return httpx.Response(201, json=t)
        m = re.match(r"groups/(\w+)/sites/root$", path)
        if m:
            return httpx.Response(200, json={"id": f"site-{m.group(1)}",
                                             "webUrl": f"https://vendettacd.sharepoint.com/sites/{m.group(1)}"})
        m = re.match(r"groups/(\w+)/drive$", path)
        if m:
            return httpx.Response(200, json={"id": f"drive-{m.group(1)}"})
        m = re.match(r"drives/([\w-]+)/root:/(.+?)(:/children)?$", path)
        if m:
            drive, fpath, children = m.group(1), m.group(2), m.group(3)
            if children:
                key = f"{drive}/{fpath}/{body['name']}"
                if key in self.items:
                    return httpx.Response(409)
                self.items[key] = {"id": f"i{len(self.items)}", "webUrl": f"https://sp.example/{key}"}
                return httpx.Response(201, json=self.items[key])
            key = f"{drive}/{fpath}"
            return httpx.Response(200, json=self.items[key]) if key in self.items else httpx.Response(404)
        m = re.match(r"drives/([\w-]+)/root/children$", path)
        if m:
            key = f"{m.group(1)}/{body['name']}"
            if key in self.items:
                return httpx.Response(409)
            self.items[key] = {"id": f"i{len(self.items)}", "webUrl": f"https://sp.example/{key}"}
            return httpx.Response(201, json=self.items[key])
        m = re.match(r"drives/([\w-]+)/items/([\w-]+)/invite$", path)
        if m:
            self.invites.append(body)
            return httpx.Response(200, json={"value": []})
        m = re.match(r"drives/([\w-]+)/items/([\w-]+)/copy$", path)
        if m:
            self.copies.append({"src": m.group(2), **body})
            return httpx.Response(202)
        m = re.match(r"drives/([\w-]+)/items/([\w-]+)$", path)
        if m:
            item = next((v for v in self.items.values() if v["id"] == m.group(2)), None)
            return httpx.Response(200, json=item) if item else httpx.Response(404)
        if path.startswith("sites/vendettacd.sharepoint.com:"):
            return httpx.Response(200, json={"id": "site-tools"})
        if path == "sites/site-tools/drive":
            return httpx.Response(200, json={"id": "lib"})
        return httpx.Response(404, json={"error": {"message": f"fake has no {request.method} {path}"}})


class FakeServices:
    """IR hub, OSP, SuperOps, Slack and the Teams delivery webhook."""

    def __init__(self):
        self.hub_calls: list[dict] = []
        self.osp_calls: list[dict] = []
        self.milestones: list[str] = []
        self.tickets: list[dict] = []
        self.slack: list[tuple] = []
        self.teams_cards: list[dict] = []
        self.hub_down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url, body = str(request.url), (json.loads(request.content) if request.content else {})
        if url.startswith("https://hub.test/api/ir-cases/open"):
            if self.hub_down:
                return httpx.Response(500)
            self.hub_calls.append(body)
            return httpx.Response(200, json={"case_id": "VCD-IR-2026-782", "id": "case-1", "existing": False})
        if url.startswith("https://hub.test/api/ir-cases/") or url.startswith("https://osp.test/api/engagements/"):
            self.milestones.append(url)
            return httpx.Response(200, json={"ok": True})
        if url == "https://osp.test/api/engagements":
            self.osp_calls.append(body)
            return httpx.Response(201, json={"id": "osp-9", "name": body["name"]})
        if url == "https://superops.test/msp":
            assert request.headers["CustomerSubDomain"] == "vendettacd"
            if "getClientList" in body["query"]:
                return httpx.Response(200, json={"data": {"getClientList": {"clients": [
                    {"accountId": "acc-ifb", "name": "IFB"}]}}})
            self.tickets.append(body["variables"]["input"])
            return httpx.Response(200, json={"data": {"createTicket": {"ticketId": "t-1", "displayId": "T1042"}}})
        if url.startswith("https://slack.test/api/"):
            method = url.rsplit("/", 1)[1]
            self.slack.append((method, body))
            if method == "conversations.create":
                return httpx.Response(200, json={"ok": True, "channel": {"id": "C1", "name": body["name"]}})
            if method == "users.lookupByEmail":
                if body["email"].startswith("ghost"):
                    return httpx.Response(200, json={"ok": False, "error": "users_not_found"})
                return httpx.Response(200, json={"ok": True, "user": {"id": "U" + body["email"][:3]}})
            return httpx.Response(200, json={"ok": True, "ts": "1.2"})
        if url == "https://teams.webhook.test/x":
            self.teams_cards.append(body)
            return httpx.Response(200)
        return httpx.Response(404)


@pytest.fixture()
def world(client, monkeypatch):
    from app import harvest, integrations, kickoff, m365, milestones, slack, superops
    from app.config import alert_settings, settings
    hv, ws, svc = KickoffHarvest(), FakeWorkspace(), FakeServices()
    harvest.TRANSPORT = httpx.MockTransport(hv.handler)
    harvest._USERS.update(at=0.0, by_email={})
    m365.TRANSPORT = httpx.MockTransport(ws.handler)
    m365._TOKEN.update(value="")
    m365.SLEEP = lambda s: None
    for mod in (kickoff, milestones, slack, superops):
        monkeypatch.setattr(mod, "TRANSPORT", httpx.MockTransport(svc.handler))
    monkeypatch.setattr(kickoff, "BACKGROUND", False)
    for k, v in {"platform_hub_url": "https://hub.test", "osp_url": "https://osp.test",
                 "superops_api_url": "https://superops.test/msp", "superops_api_token": "so-token",
                 "superops_subdomain": "vendettacd", "slack_bot_token": "xoxb-1", "slack_api_url": "https://slack.test/api",
                 "slack_announce_channel": "#delivery", "kickoff_core_team": "kenedi@vendettacd.io",
                 "kickoff_tools_site_url": "https://vendettacd.sharepoint.com/sites/Tools",
                 "kickoff_tools_folder": "tools", "kickoff_team_poll_seconds": 0}.items():
        monkeypatch.setattr(settings, k, v)
    monkeypatch.setattr(alert_settings, "teams_webhook_url", "https://teams.webhook.test/x")
    integrations.save({"harvest_account_id": "acct-1", "harvest_token": "hv-token", "graph_tenant_id": "tid",
                       "graph_client_id": "cid", "graph_client_secret": "sec"}, "test")
    hv.users.append({"id": 14, "email": "kenedi@vendettacd.io", "name": "Kenedi"})
    add_user("pm@vendettacd.io")
    mcp = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    yield {"mcp": mcp, "harvest": hv, "graph": ws, "svc": svc, "client": client}
    harvest.TRANSPORT = None
    m365.TRANSPORT = None


def _status(out: dict) -> dict:
    return {s["step"]: s["status"] for s in out["steps"]}


# ---------------------------------------------------------------- tests
def test_ir_kickoff_opens_everything_and_links_it(world):
    mcp, ws, hv, svc = world["mcp"], world["graph"], world["harvest"], world["svc"]
    opts = mcp.ok("kickoff_options", practice="ir")
    assert all(opts["integrations"].values())
    assert "Forensics" in opts["practices"]["ir"]["tags"]
    out = mcp.ok("kickoff_engagement", practice="ir", client="IFB", engagement_type="bec", lead="dan@vendettacd.io",
                 summary="CFO mailbox compromise, wire fraud attempt", budget_hours=40,
                 team=[{"email": "craig@vendettacd.io", "tags": ["Forensics"]}],
                 client_contacts=["htorres@ifbbank.com"], client_tools=["crowdstrike-sensor"], slack="channel")
    assert out["code"] == "VCD-IR-2026-782"  # the firm-wide case number from the IR hub
    st = _status(out)
    assert st.pop("mailbox") == "waiting"
    assert set(st.values()) == {"ok"}, [s for s in out["steps"] if s["status"] != "ok"]
    assert out["status"] == "waiting" and out["follow_ups_for_claude"] == []

    # Microsoft 365: one group with the case mailbox, the team, threads channels, tags, folders, sharing
    grp = next(iter(ws.groups.values()))
    assert grp["mailNickname"] == "ir-782" and grp["body"]["visibility"] == "Private"
    assert out["links"]["mailbox"] == "ir-782@vendettacd.io"
    assert {b["displayName"] for b in ws.channel_bodies} >= {"Forensics and Analysis", "Case Management"}
    assert all(b.get("layoutType") == "chat" for b in ws.channel_bodies)
    assert next(b for b in ws.channel_bodies if b["displayName"] == "Case Management")["membershipType"] == "private"
    forensics = next(t for t in ws.tags["g1"] if t["displayName"] == "Forensics")
    assert {"userId": "u-craig"} in forensics["members"] and {"userId": "u-dan"} in forensics["members"]
    assert "drive-g1/Evidence/Malware" in ws.items and "drive-g1/Client Uploads/Vendetta Tools" in ws.items
    assert ws.invites == [{"recipients": [{"email": "htorres@ifbbank.com"}], "requireSignIn": True,
                           "sendInvitation": True, "roles": ["write"], "message": ws.invites[0]["message"]}]
    assert ws.copies and ws.copies[0]["src"] == "src-cs"

    # Harvest project under the case code, tasks and team assigned
    assert hv.project_posts == 1
    proj = hv.projects[-1]
    assert proj["code"] == "VCD-IR-2026-782" and proj["budget"] == 40
    assert {t["task"]["name"] for t in hv.tasks[proj["id"]]} == {"Incident Response", "Forensic Analysis",
                                                                    "Project Management", "Report Writing"}
    assert {u["user"]["id"] for u in hv.user_assign[proj["id"]]} >= {11, 12, 14}

    # SuperOps, Slack, Teams
    assert svc.tickets[0]["client"] == {"accountId": "acc-ifb"} and svc.tickets[0]["ticketType"] == "Incident"
    assert out["links"]["superops_ticket"] == "T1042"
    methods = [m for m, _ in svc.slack]
    assert "conversations.create" in methods and "conversations.inviteShared" in methods
    assert "chat.postMessage" in methods
    assert svc.teams_cards and "VCD-IR-2026-782" in json.dumps(svc.teams_cards[0])
    assert svc.hub_calls[0]["client"] == "IFB" and svc.hub_calls[0]["source_module"] == "project-management"

    # The engagement carries the links, and has its BEC template tasks
    eng = mcp.ok("get_engagement", engagement="VCD-IR-2026-782")
    assert eng["harvest_project_id"] == str(proj["id"]) and eng["platform_ref"] == "VCD-IR-2026-782"
    assert eng["sharepoint"]["site"] == "https://vendettacd.sharepoint.com/sites/g1"
    assert eng["type"] == "bec" and eng["tasks"]["open"] > 0
    assert eng["lead"] == "dan@vendettacd.io" and eng["phase"] == "Engaged"


def test_retry_never_duplicates(world):
    mcp, ws, hv, svc = world["mcp"], world["graph"], world["harvest"], world["svc"]
    out = mcp.ok("kickoff_engagement", practice="ir", client="IFB", client_contacts=["a@ifbbank.com"])
    again = mcp.ok("retry_kickoff", kickoff=out["code"],
                   steps=["harvest", "m365_workspace", "client_uploads", "superops"],
                   client_contacts=["b@ifbbank.com"])
    assert _status(again)["client_uploads"] == "ok"
    assert ws.group_posts == 1 and hv.project_posts == 1 and len(svc.tickets) == 1
    assert [i["recipients"] for i in ws.invites] == [[{"email": "a@ifbbank.com"}], [{"email": "b@ifbbank.com"}]]
    assert len([b for b in ws.channel_bodies if b["displayName"] == "Threat Intel"]) == 1


def test_mailbox_worker_closes_the_step(world):
    from app import auth
    mcp, client = world["mcp"], world["client"]
    out = mcp.ok("kickoff_engagement", practice="ir", client="IFB", superops=False, slack="none")
    hdr = {"Authorization": f"Bearer {auth.api_token()}"}
    jobs = client.post("/api/kickoff-worker/mailbox/claim", headers=hdr).json()["jobs"]
    assert len(jobs) == 1 and jobs[0]["address"] == "ir-782@vendettacd.io"
    assert "kenedi@vendettacd.io" in jobs[0]["members"]
    assert client.post("/api/kickoff-worker/mailbox/claim", headers=hdr).json()["jobs"] == []
    r = client.post(f"/api/kickoff-worker/mailbox/{jobs[0]['id']}", headers=hdr,
                    json={"status": "done", "detail": "external senders on"})
    assert r.status_code == 200
    done = mcp.ok("kickoff_status", kickoff=out["code"])
    assert _status(done)["mailbox"] == "ok" and done["status"] == "complete"


def test_hub_down_blocks_an_ir_engagement(world):
    world["svc"].hub_down = True
    res = world["mcp"].call("kickoff_engagement", practice="ir", client="IFB")
    out = res["structuredContent"]
    assert out["status"] == "failed" and _status(out)["platform_record"] == "failed"
    assert _status(out)["engagement"] == "blocked"
    assert world["mcp"].ok("list_engagements")["engagements"] == []


def test_proserv_without_integrations_skips_and_hands_off_to_claude(world, monkeypatch):
    from app import integrations
    from app.config import alert_settings, settings
    for k in ("osp_url", "superops_api_token", "slack_bot_token", "slack_announce_channel"):
        monkeypatch.setattr(settings, k, "")
    monkeypatch.setattr(settings, "kickoff_m365_enabled", False)
    monkeypatch.setattr(alert_settings, "teams_webhook_url", "")
    integrations.save({"harvest_account_id": "", "harvest_token": ""}, "test")
    mcp = world["mcp"]
    out = mcp.ok("kickoff_engagement", practice="proserv", client="Rize CU", engagement_type="tabletop",
                 name="Rize tabletop exercise", budget_hours=24)
    st = _status(out)
    assert out["code"].startswith("VCD-PS-") and st["engagement"] == "ok"
    assert {st[k] for k in ("platform_record", "harvest", "m365_workspace", "superops", "announce")} == {"skipped"}
    assert any("SuperOps connector" in f for f in out["follow_ups_for_claude"])
    linked = mcp.ok("record_kickoff_link", kickoff=out["code"], system="superops", ref="T2001")
    assert _status(linked)["superops"] == "ok" and linked["links"]["superops_ticket"] == "T2001"


def test_proserv_opens_osp_engagement_and_publishes(world):
    out = world["mcp"].ok("kickoff_engagement", practice="proserv", client="Rize CU", engagement_type="pentest",
                          slack="none", superops=False)
    assert _status(out)["platform_record"] == "ok"
    assert world["svc"].osp_calls[0]["kind"] == "assessment"
    eng = world["mcp"].ok("get_engagement", engagement=out["code"])
    assert eng["platform_ref"] == "osp-9"
    assert grp_nick(world) == "ps-" + out["code"].rsplit("-", 1)[1]
    assert any("osp.test/api/engagements/osp-9/milestones" in u for u in world["svc"].milestones)


def grp_nick(world) -> str:
    return next(iter(world["graph"].groups.values()))["mailNickname"]


def test_tenant_without_threads_layout_still_gets_channels(world):
    world["graph"].reject_layout = True
    out = world["mcp"].ok("kickoff_engagement", practice="ir", client="IFB", superops=False, slack="none")
    assert _status(out)["m365_workspace"] == "ok"
    assert "default layout" in next(s["detail"] for s in out["steps"] if s["step"] == "m365_workspace")
    assert world["graph"].channel_bodies and all("layoutType" not in b for b in world["graph"].channel_bodies)


def test_unknown_client_tool_is_refused(world):
    res = world["mcp"].call("kickoff_engagement", practice="ir", client="IFB", client_tools=["mimikatz"])
    assert res["isError"] and "Unknown client tool" in res["content"][0]["text"]


def test_viewer_cannot_kick_off(client):
    add_user("viewer@vendettacd.io", role="viewer")
    mcp = Mcp(client, connect_claude(client, "viewer@vendettacd.io")["access_token"])
    res = mcp.call("kickoff_engagement", practice="ir", client="IFB")
    assert res["isError"] and "read-only" in res["content"][0]["text"]
