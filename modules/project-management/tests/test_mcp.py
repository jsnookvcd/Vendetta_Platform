"""The Claude connector: OAuth 2.1 with PKCE, then the MCP tools end to end."""
from urllib.parse import parse_qs, urlparse

from conftest import CLAUDE_CB, Mcp, add_user, as_user, connect_claude, pkce

from app.db import Card, MeetingNote, SessionLocal, User


def test_metadata_and_401_challenge(client):
    pr = client.get("/.well-known/oauth-protected-resource").json()
    assert pr["resource"] == "https://pm.test.example/mcp"
    assert pr["authorization_servers"] == ["https://pm.test.example"]
    asm = client.get("/.well-known/oauth-authorization-server").json()
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["registration_endpoint"].endswith("/oauth/register")
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r.status_code == 401
    assert 'resource_metadata="https://pm.test.example/.well-known/oauth-protected-resource"' \
        in r.headers["www-authenticate"]
    bad = client.post("/mcp", json={}, headers={"Authorization": "Bearer vpm_at_nope"})
    assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]


def test_registration_only_for_allowlisted_redirects(client):
    assert client.post("/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]}).status_code == 400
    assert client.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB]}).status_code == 201
    assert client.post("/oauth/register", json={"redirect_uris": ["http://localhost:53682/callback"]}).status_code == 201
    assert client.post("/oauth/register", json={"redirect_uris": ["https://localhost/cb"]}).status_code == 400


def test_authorize_sends_anonymous_to_login_and_enforces_pkce(client):
    cid = client.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB]}).json()["client_id"]
    _v, ch = pkce()
    q = {"response_type": "code", "client_id": cid, "redirect_uri": CLAUDE_CB, "code_challenge": ch,
         "code_challenge_method": "S256", "state": "s"}
    r = client.get("/oauth/authorize", params=q, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login?next=%2Foauth%2Fauthorize")
    no_pkce = {**q, "code_challenge_method": "plain"}
    add_user("pm@vendettacd.io")
    as_user(client, "pm@vendettacd.io")
    r = client.get("/oauth/authorize", params=no_pkce, follow_redirects=False)
    assert r.status_code == 302 and "error=invalid_request" in r.headers["location"]
    r = client.get("/oauth/authorize", params={**q, "redirect_uri": "https://claude.com/api/mcp/auth_callback"})
    assert r.status_code == 400  # not the URI this client registered


def test_wrong_verifier_and_code_reuse_rejected(client):
    add_user("pm@vendettacd.io")
    cid = client.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB]}).json()["client_id"]
    verifier, ch = pkce()
    as_user(client, "pm@vendettacd.io")
    page = client.get("/oauth/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": CLAUDE_CB,
                                                  "code_challenge": ch, "code_challenge_method": "S256"})
    csrf = page.text.split('name="csrf" value="')[1].split('"')[0]
    r = client.post("/oauth/authorize", data={"csrf": csrf, "decision": "approve", "client_id": cid,
                                              "redirect_uri": CLAUDE_CB, "code_challenge": ch}, follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    bad = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": cid,
                                            "redirect_uri": CLAUDE_CB, "code_verifier": pkce()[0]})
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    again = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": cid,
                                              "redirect_uri": CLAUDE_CB, "code_verifier": verifier})
    assert again.status_code == 400  # a code is single use, even after a failed attempt


def test_refresh_rotates(client):
    add_user("pm@vendettacd.io")
    tok = connect_claude(client, "pm@vendettacd.io")
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                          "client_id": tok["client_id"]})
    assert r.status_code == 200 and r.json()["refresh_token"] != tok["refresh_token"]
    again = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                              "client_id": tok["client_id"]})
    assert again.status_code == 400
    assert Mcp(client, r.json()["access_token"]).rpc("ping").json()["result"] == {}


def test_initialize_list_and_full_pm_flow(client):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    init = m.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "claude", "version": "1"}}).json()["result"]
    assert init["protocolVersion"] == "2025-06-18" and "tools" in init["capabilities"]
    assert client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                       headers={"Authorization": f"Bearer {m.token}"}).status_code == 202
    names = {t["name"] for t in m.rpc("tools/list").json()["result"]["tools"]}
    assert {"create_engagement", "create_task", "move_task", "log_time", "log_meeting_notes",
            "manage_board_column", "remove_task"} <= names

    e = m.ok("create_engagement", practice="ir", name="BEC response", client="North Central")
    assert e["code"].startswith("VCD-IR-") and e["phase"] == "Intake" and e["pm"] == "pm@vendettacd.io"
    m.ok("move_engagement", engagement=e["code"], phase="scoping")
    assert m.ok("get_engagement", engagement="BEC")["phase"] == "Scoping and Containment"

    t = m.ok("create_task", engagement=e["code"], title="Pull UAL", assignee="me", due_on="2020-01-01",
             labels=["Forensics and Analysis"])
    many = m.ok("create_tasks", engagement=e["code"], tasks=[{"title": "Reset creds", "priority": "urgent"},
                                                             {"title": "Notify carrier", "column": "Backlog"}])
    assert many["created"] == 2
    mine = m.ok("list_tasks", assignee="me")
    assert [x["ref"] for x in mine["tasks"]] == [t["ref"]] and mine["tasks"][0]["overdue"]
    m.ok("move_task", task=f"#{t['ref']}", column="in prog")
    m.ok("update_task", task=str(t["ref"]), checklist_add=["export", "hash"], checklist_check=[1])
    m.ok("comment_on_task", task=str(t["ref"]), text="tenant admin granted access")
    got = m.ok("get_task", task=str(t["ref"]))
    assert got["column"] == "In Progress" and got["checklist"] == "1/2"
    assert any(h["kind"] == "comment" for h in got["history"])

    board = m.ok("get_board", board=e["code"])
    assert next(c for c in board["columns"] if c["name"] == "In Progress")["count"] == 1
    m.ok("manage_board_column", board=e["code"], action="add", name="Waiting on Client", position=4)
    err = m.call("manage_board_column", board=e["code"], action="remove", column="backlog")
    assert err["isError"] and "move them to" in err["content"][0]["text"]
    m.ok("manage_board_column", board=e["code"], action="remove", column="backlog", move_cards_to="To Do")
    cols = m.ok("get_board", board=e["code"])["columns"]
    assert "Backlog" not in [c["name"] for c in cols] and cols[3]["name"] == "Waiting on Client"

    removed = m.ok("remove_task", task=str(many["tasks"][0]["ref"]))
    assert removed["archived"] == many["tasks"][0]["ref"]
    m.ok("restore_task", task=str(many["tasks"][0]["ref"]))
    m.ok("remove_task", task=str(many["tasks"][0]["ref"]), mode="delete")
    assert SessionLocal().query(Card).filter_by(title="Reset creds").count() == 0

    note = m.ok("log_meeting_notes", engagement=e["code"], title="Kickoff", body="# Scope\n- M365 only",
                decisions="Contain first", action_items=[{"text": "Send preservation letter", "assignee": "me",
                                                          "due_on": "2026-10-21"}])
    assert note["sharepoint"]["status"] == "off" and note["action_items"][0]["card_ref"]
    assert m.ok("list_tasks", engagement=e["code"], label="action item")["count"] == 1
    m.ok("update_meeting_note", note_id=note["id"], append="Follow-up: carrier on the call")
    assert "carrier" in m.ok("get_meeting_note", note_id=note["id"])["body"]
    assert m.ok("list_meeting_notes", query="preservation")["count"] == 0  # action items are not body text
    assert m.ok("list_meeting_notes", query="carrier")["count"] == 1

    blocked = m.call("update_engagement", engagement=e["code"], status="closed")
    assert blocked["isError"] and "closeout item" in blocked["content"][0]["text"]
    closed = m.ok("update_engagement", engagement=e["code"], status="closed", force=True)
    assert closed["phase"] == "Closed"
    mw = m.ok("my_work", include_time=False)
    assert mw["engagements"] == []


def test_tool_errors_are_readable_and_unknown_args_refused(client):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    r = m.call("get_engagement", engagement="nothing-like-this")
    assert r["isError"] and "No engagement matches" in r["content"][0]["text"]
    r = m.call("create_task", engagement="x", title="t", bogus=1)
    assert r["isError"] and "bogus" in r["content"][0]["text"]
    r = m.call("create_task", title="t")
    assert r["isError"] and "engagement" in r["content"][0]["text"]
    assert m.rpc("nope/method").json()["error"]["code"] == -32601


def test_viewer_gets_read_tools_only(client):
    add_user("viewer@vendettacd.io", "viewer")
    m = Mcp(client, connect_claude(client, "viewer@vendettacd.io")["access_token"])
    names = {t["name"] for t in m.rpc("tools/list").json()["result"]["tools"]}
    assert "list_tasks" in names and "create_task" not in names and "log_time" not in names
    r = m.call("create_engagement", practice="ir", name="x")
    assert r["isError"] and "read-only" in r["content"][0]["text"]


def test_deactivation_cuts_the_connector_off(client):
    add_user("pm@vendettacd.io")
    m = Mcp(client, connect_claude(client, "pm@vendettacd.io")["access_token"])
    assert m.rpc("ping").status_code == 200
    db = SessionLocal()
    db.query(User).filter_by(email="pm@vendettacd.io").update({"active": False})
    db.commit()
    assert m.rpc("ping").status_code == 401


def test_personal_access_token_and_revoke(client):
    add_user("pm@vendettacd.io")
    as_user(client, "pm@vendettacd.io")
    client.post("/connect/tokens", data={"name": "Claude Code", "days": "30"}, follow_redirects=False)
    page = client.get("/connect").text
    raw = page.split("vpm_pat_")[1].split("<")[0]
    raw = "vpm_pat_" + raw.strip()
    m = Mcp(client, raw)
    assert m.ok("whoami")["email"] == "pm@vendettacd.io"
    assert client.get("/api/tasks", headers={"Authorization": f"Bearer {raw}"}).status_code == 200
    client.post("/connect/revoke-all")
    assert m.rpc("ping").status_code == 401


def test_meeting_note_action_items_written_through_web_form(admin):
    r = admin.post("/engagements", data={"practice": "proserv", "name": "Tabletop", "client": "BMA"},
                   follow_redirects=False)
    eid = r.headers["location"].split("/engagements/")[1].split("?")[0]
    admin.post(f"/engagements/{eid}/notes", data={
        "title": "Planning call", "body": "scenario draft", "create_tasks": "true",
        "action_items": "Draft injects @dan@vendettacd.io due 2026-11-02\nBook room"})
    db = SessionLocal()
    n = db.query(MeetingNote).filter_by(engagement_id=eid).one()
    assert [a["text"] for a in n.action_items] == ["Draft injects", "Book room"]
    t = db.query(Card).filter_by(title="Draft injects").one()
    assert t.assignee == "dan@vendettacd.io" and str(t.due_on) == "2026-11-02"
