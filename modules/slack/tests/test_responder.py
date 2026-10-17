"""The responder end to end against a fake Slack, control plane, IR hub and SABINE.
Every case change must reach the IR hub with the person named; every refusal must
be audited; nothing outside the staff roster can act."""
import hashlib
import hmac
import json
import time

from app import blocks, feed, identity, responder, slack, socketmode
from app.db import AuditLog, Posted, SessionLocal, WarRoom

from conftest import cmd


def _texts(world, method="chat.postMessage", channel=None):
    return [p.get("text", "") for p in world.slack(method) if channel is None or p.get("channel") == channel]


def _ephemerals(world):
    return [r[1].get("text", "") for r in world.responses]


def _room(world, user="U_DAN"):
    """Declare a case with a war room and return (case, room)."""
    responder.handle_command(cmd("declare critical riverbend: ransom note on FS01", user=user))
    db = SessionLocal()
    room = db.query(WarRoom).one()
    return world.cases[room.case_number], room


# ---------------------------------------------------------------- Slack's request signature
def _sign(body: bytes, ts: int | None = None, secret: str = "shh-signing") -> dict:
    ts = ts or int(time.time())
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + str(ts).encode() + b":" + body, hashlib.sha256).hexdigest()
    return {"x-slack-request-timestamp": str(ts), "x-slack-signature": sig}


def test_signature_good_bad_stale():
    body = b"token=x&text=help"
    assert slack.verify(_sign(body), body)
    assert not slack.verify(_sign(body, secret="wrong"), body)
    assert not slack.verify(_sign(body, ts=int(time.time()) - 600), body)
    assert not slack.verify({}, body)


def test_http_commands_need_a_valid_signature(client, world):
    body = b"team_id=T_VCD&user_id=U_DAN&channel_id=C1&text=help&response_url=https%3A%2F%2Fhooks.slack.com%2Fx"
    assert client.post("/slack/commands", content=body).status_code == 401
    r = client.post("/slack/commands", content=body,
                    headers={**_sign(body), "content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200
    assert any("Slack responder" in t for t in _ephemerals(world))


def test_events_url_verification_and_retries(client, world):
    body = json.dumps({"type": "url_verification", "challenge": "abc"}).encode()
    assert client.post("/slack/events", content=body).status_code == 401
    assert client.post("/slack/events", content=body, headers=_sign(body)).json() == {"challenge": "abc"}


def test_response_url_must_be_slacks_own(world):
    assert slack.respond("https://evil.example/hook", {"text": "x"}) is False
    assert not world.responses


# ---------------------------------------------------------------- identity
def test_outsiders_and_unrostered_people_are_refused_and_audited(world):
    responder.handle_command(cmd("cases", user="U_OUT"))
    responder.handle_command(cmd("cases", user="U_NOBODY"))
    msgs = _ephemerals(world)
    assert any("Vendetta domain" in m for m in msgs) and any("not on the platform staff roster" in m for m in msgs)
    rows = SessionLocal().query(AuditLog).filter(AuditLog.ok.is_(False)).all()
    assert len(rows) == 2 and all(r.action == "refused.cases" for r in rows)
    assert not world.ir("/api/ir-cases")


def test_no_roster_yet_refuses_everyone(world):
    world.governs = False
    responder.handle_command(cmd("cases", user="U_JORDAN"))
    assert any("not on the platform staff roster" in m for m in _ephemerals(world))


def test_platform_down_before_first_roster_fails_closed(world):
    world.platform_up = False
    responder.handle_command(cmd("cases"))
    assert any("cannot reach the staff roster" in m for m in _ephemerals(world))


def test_last_good_roster_survives_a_platform_outage(world):
    responder.handle_command(cmd("cases"))
    world.platform_up = False
    identity._ROSTER["incident-response"]["at"] = 0  # cache expired
    world.responses.clear()
    responder.handle_command(cmd("cases"))
    assert any("No active cases" in m for m in _ephemerals(world))


def test_deactivation_takes_effect_on_the_next_command_after_a_push(client, world):
    responder.handle_command(cmd("cases"))
    world.roster["incident-response"] = [r for r in world.roster["incident-response"] if r["email"] != "dan@vendettacd.io"]
    r = client.post("/api/provision/sync", headers={"Authorization": f"Bearer {__import__('app.auth', fromlist=['x']).api_token()}"})
    assert r.json()["ok"] is True
    world.responses.clear()
    responder.handle_command(cmd("cases"))
    assert any("not on the platform staff roster" in m for m in _ephemerals(world))


# ---------------------------------------------------------------- declare and the war room
def test_text_declare_opens_case_war_room_and_announces(world):
    case, room = _room(world)
    decl = world.ir("/api/ir-cases/declare")[0]
    assert decl["person"] == "dan@vendettacd.io" and decl["actor"] == "slack"
    assert decl["body"]["platform_client_id"] == "plat-rb" and decl["body"]["severity"] == "critical"
    created = world.slack("conversations.create")[0]
    assert created["name"] == f"ir-{case['number'].lower()}" and created["is_private"] is True
    invited = {p["users"] for p in world.slack("conversations.invite")}
    assert {"U_DAN", "U_LEADER"} <= invited
    assert world.slack("pins.add") and world.slack("conversations.setTopic")
    assert "CRITICAL | Riverbend Credit Union | open" in world.slack("conversations.setTopic")[0]["topic"]
    notes = [c["body"]["note"] for c in world.ir("/updates")]
    assert any(n.startswith("War room opened in Slack") for n in notes)
    assert any(p.get("channel") == "C_IR" for p in world.slack("chat.postMessage"))
    assert SessionLocal().query(Posted).filter_by(kind="case", ref=case["number"]).one().ts
    assert any(f"{case['number']} is open" in m for m in _ephemerals(world))


def test_ambiguous_client_asks_and_viewer_cannot_declare(world):
    responder.handle_command(cmd("declare high river: something"))
    assert any("More than one client matches" in m for m in _ephemerals(world))
    responder.handle_command(cmd("declare high riverbend: x", user="U_VIEW"))
    assert any("read but not work cases" in m for m in _ephemerals(world))
    assert not world.ir("/api/ir-cases/declare")


def test_declare_modal_opens_and_validates(world):
    ack = responder.handle_command(cmd("declare"))
    assert ack is None and world.slack("views.open")
    view = world.slack("views.open")[0]["view"]
    assert view["callback_id"] == "declare" and len(view["blocks"][0]["element"]["options"]) == 3
    sub = {"type": "view_submission", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"},
           "view": {"callback_id": "declare", "private_metadata": "C_GENERAL", "state": {"values": {
               "client": {"v": {"selected_option": {"value": "plat-hp"}}},
               "severity": {"v": {"selected_option": {"value": "high"}}},
               "desc": {"v": {"value": ""}}, "room": {"v": {"selected_options": []}}}}}}
    assert responder.handle_interaction(sub)["response_action"] == "errors"
    sub["view"]["state"]["values"]["desc"]["v"]["value"] = "Phishing wave, three mailboxes"
    assert responder.handle_interaction(sub) is None
    d = world.ir("/api/ir-cases/declare")[0]
    assert d["body"]["platform_client_id"] == "plat-hp" and d["person"] == "dan@vendettacd.io"
    assert not world.slack("conversations.create")  # war room box unticked


def test_viewer_gets_refused_before_the_modal(world):
    ack = responder.handle_command(cmd("declare", user="U_VIEW"))
    assert "read but not work cases" in ack["text"] and not world.slack("views.open")


# ---------------------------------------------------------------- working a case in the war room
def test_note_status_sev_lead_task_page_in_the_war_room(world):
    case, room = _room(world)
    ch = room.channel_id
    world.slack_calls.clear()

    responder.handle_command(cmd("note forensics: beacon to <https://203.0.113.9|203.0.113.9> every 60s, <@U_JORDAN> confirmed", channel=ch))
    note = world.ir("/updates")[-1]
    assert note["person"] == "dan@vendettacd.io" and note["body"]["workstream"] == "Forensics and Analysis"
    assert "203.0.113.9 (https://203.0.113.9)" in note["body"]["note"] and "@Jordan Snook" in note["body"]["note"]
    assert note["body"]["internal_only"] is True
    assert any("Dan logged to" in t for t in _texts(world, channel=ch))

    responder.handle_command(cmd("contained", channel=ch))
    assert world.ir("/status")[-1]["body"] == {"status": "contained"}
    assert any("contained" in p["topic"] for p in world.slack("conversations.setTopic"))
    assert world.slack("chat.update")  # pinned card follows

    responder.handle_command(cmd("sev high", channel=ch))
    assert world.ir("/details")[-1]["body"] == {"severity": "high"}

    responder.handle_command(cmd("lead <@U_JORDAN|jordan>", channel=ch))
    assert world.ir("/details")[-1]["body"] == {"lead": "Jordan Snook"}

    responder.handle_command(cmd("task recovery: restore FS01 from Tuesday <@U_JORDAN>", channel=ch))
    t = world.ir("/tasks")[-1]["body"]
    assert t == {"workstream": "Recovery and Restoration", "title": "restore FS01 from Tuesday", "owner": "Jordan Snook"}

    responder.handle_command(cmd("page need a second forensic examiner", channel=ch))
    pg = world.ir("/api/oncall/page")[-1]["body"]
    assert pg["source_ref"] == case["number"] and "War room" in pg["body"] and pg["severity"] == "high"

    acts = {r.action for r in SessionLocal().query(AuditLog).filter(AuditLog.ok.is_(True)).all()}
    assert {"case.note", "case.status", "case.severity", "case.lead", "case.task", "case.page"} <= acts


def test_viewer_reads_but_cannot_change(world):
    case, room = _room(world)
    world.responses.clear()
    responder.handle_command(cmd("sitrep", user="U_VIEW", channel=room.channel_id))
    assert any(p.get("blocks") for p in world.slack("chat.postMessage") if p.get("channel") == room.channel_id)
    n = len(world.ir("/status"))
    responder.handle_command(cmd("status closed", user="U_VIEW", channel=room.channel_id))
    assert len(world.ir("/status")) == n
    assert any("read but not work cases" in m for m in _ephemerals(world))


def test_commands_outside_a_war_room_need_a_case_number(world):
    case = world.add_case()
    responder.handle_command(cmd("note hello"))
    assert any("Which case?" in m for m in _ephemerals(world))
    responder.handle_command(cmd(f"note {case['number']} hello from general"))
    assert world.ir("/updates")[-1]["path"] == f"/api/ir-cases/{case['number']}/updates"


def test_task_overflow_moves_the_card(world):
    case, room = _room(world)
    payload = {"type": "block_actions", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"},
               "channel": {"id": "C_GENERAL"}, "response_url": "https://hooks.slack.com/actions/x",
               "actions": [{"action_id": "task_move", "selected_option": {"value": f"{case['number']}|t1|done"}}]}
    responder.handle_interaction(payload)
    assert world.ir("/tasks/t1/move")[-1]["body"] == {"status": "done"}
    assert any("finished: Isolate affected hosts" in t for t in _texts(world, channel=room.channel_id))


# ---------------------------------------------------------------- logging Slack messages to the timeline
def test_memo_reaction_logs_once_with_the_permalink(world):
    case, room = _room(world)
    ch = room.channel_id
    world.history[(ch, "1700000000.000100")] = {"ts": "1700000000.000100", "user": "U_JORDAN",
                                                "text": "FS01 shows vssadmin delete shadows at 02:14", "files": [{"name": "ps.txt"}]}
    ev = {"team_id": "T_VCD", "event": {"type": "reaction_added", "user": "U_DAN", "reaction": "memo",
                                        "item": {"type": "message", "channel": ch, "ts": "1700000000.000100"}}}
    responder.handle_event(ev)
    entry = world.ir("/updates")[-1]
    assert entry["person"] == "dan@vendettacd.io"
    assert "Jordan Snook" in entry["body"]["note"] and "vssadmin" in entry["body"]["note"] and "ps.txt" in entry["body"]["note"]
    assert entry["body"]["source"].startswith("https://vcd.slack.com/archives/")
    assert world.slack("reactions.add")[-1]["name"] == "white_check_mark"
    n = len(world.ir("/updates"))
    responder.handle_event(ev)  # a second memo on the same message
    assert len(world.ir("/updates")) == n


def test_memo_outside_a_war_room_or_by_the_bot_does_nothing(world):
    ev = {"team_id": "T_VCD", "event": {"type": "reaction_added", "user": "U_DAN", "reaction": "memo",
                                        "item": {"type": "message", "channel": "C_RANDOM", "ts": "1.1"}}}
    responder.handle_event(ev)
    ev["event"]["user"] = "U_BOT"
    responder.handle_event(ev)
    assert not world.ir("/updates")


def test_message_shortcut_in_unbound_channel_opens_case_picker(world):
    case = world.add_case()
    payload = {"type": "message_action", "callback_id": "log_to_case", "team": {"id": "T_VCD"},
               "user": {"id": "U_DAN"}, "channel": {"id": "C_SOC"}, "trigger_id": "trig",
               "message": {"ts": "1700000001.000200", "user": "U_JORDAN", "text": "user reports MFA prompts at 3am"}}
    responder.handle_interaction(payload)
    view = world.slack("views.open")[-1]["view"]
    assert view["callback_id"] == "log_to_case"
    meta = json.loads(view["private_metadata"])
    sub = {"type": "view_submission", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"},
           "view": {"callback_id": "log_to_case", "private_metadata": view["private_metadata"], "state": {"values": {
               "case": {"v": {"selected_option": {"value": case["number"]}}},
               "note": {"v": {"value": view["blocks"][1]["element"]["initial_value"]}}}}}}
    responder.handle_interaction(sub)
    entry = world.ir("/updates")[-1]
    assert entry["path"].endswith(f"{case['number']}/updates") and "MFA prompts" in entry["body"]["note"]
    assert entry["body"]["source"] == meta["permalink"]


# ---------------------------------------------------------------- SABINE in Slack
def test_ask_needs_a_sabine_grant_and_names_the_person(world):
    responder.handle_command(cmd("ask what is hot on riverbend"))
    assert world.sabine_calls[-1]["person"] == "dan@vendettacd.io"
    assert any("Two criticals" in m for m in _ephemerals(world))
    world.roster["sabine"] = []
    identity.reset_cache()
    n = len(world.sabine_calls)
    responder.handle_command(cmd("ask anything", user="U_DAN"))
    assert len(world.sabine_calls) == n


def test_mention_runs_a_command_or_asks(world):
    case, room = _room(world)
    responder.handle_event({"team_id": "T_VCD", "event": {"type": "app_mention", "user": "U_DAN", "channel": room.channel_id,
                                                          "ts": "5.5", "text": "<@U_BOT> what should we do next?"}})
    q = world.sabine_calls[-1]["body"]["question"]
    assert "what should we do next?" in q and case["number"] in q


def test_proposal_buttons_decide_for_the_person_and_update_the_message(world):
    world.proposal("p1")
    feed.cycle()  # seeds
    world.proposal("p2", title="Nudge the stale Harbor Point case")
    world.proposal("p3", risk="high", title="Isolate WS01")
    feed.cycle()
    posts = [p for p in world.slack("chat.postMessage") if p.get("channel") == "C_SAB"]
    assert len(posts) == 2  # p1 was there before the responder started
    p2 = next(p for p in posts if "Harbor Point" in p["text"])
    p3 = next(p for p in posts if "Isolate" in p["text"])
    ids = [e["action_id"] for b in p2["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert "proposal_approve" in ids and "proposal_reject" in ids
    ids3 = [e["action_id"] for b in p3["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert ids3 == ["open_sabine"]

    click = {"type": "block_actions", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"}, "channel": {"id": "C_SAB"},
             "container": {"message_ts": "x"}, "response_url": "https://hooks.slack.com/actions/y",
             "actions": [{"action_id": "proposal_approve", "value": "p2"}]}
    responder.handle_interaction(click)
    dec = [c for c in world.sabine_calls if c["path"].endswith("/decide")][-1]
    assert dec["person"] == "dan@vendettacd.io" and dec["body"]["approve"] is True
    upd = world.slack("chat.update")[-1]
    assert "Approved by Dan Baker in Slack" in upd["text"]

    # a viewer cannot decide
    click["user"], click["actions"] = {"id": "U_VIEW"}, [{"action_id": "proposal_reject", "value": "p1"}]
    n = len(world.sabine_calls)
    responder.handle_interaction(click)
    assert not [c for c in world.sabine_calls[n:] if c["path"].endswith("/decide")]


def test_proposal_decided_in_the_console_updates_slack(world):
    feed.cycle()  # seeds an empty proposal table
    world.proposal("p9")
    feed.cycle()
    world.proposals["p9"].update(status="rejected", decided_by="jordan@vendettacd.io")
    feed.cycle()
    upd = world.slack("chat.update")[-1]
    assert upd["text"] == "Rejected by jordan@vendettacd.io."


# ---------------------------------------------------------------- the case feed
def test_case_feed_seeds_then_announces_and_follows_changes(world):
    old = world.add_case(client="Harbor Point", pid="plat-hp")
    feed.cycle()
    assert not [p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"]
    new = world.add_case()
    feed.cycle()
    ir_posts = [p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"]
    assert len(ir_posts) == 1 and new["number"] in ir_posts[0]["text"] and old["number"] not in ir_posts[0]["text"]
    feed.cycle()
    assert len([p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"]) == 1

    case, room = _room(world)
    feed.cycle()
    case["status"] = "eradicated"  # changed in the IR console
    feed.cycle()
    msgs = _texts(world, channel=room.channel_id)
    assert any("changed in the IR hub: status open to eradicated" in m for m in msgs)


# ---------------------------------------------------------------- transports and the API
def test_socket_mode_acks_with_the_envelope_id(world):
    ack = socketmode.dispatch({"type": "slash_commands", "envelope_id": "e1", "payload": cmd("declare", user="U_VIEW")})
    assert ack["envelope_id"] == "e1" and "read but not work cases" in ack["payload"]["text"]
    assert socketmode.dispatch({"type": "events_api", "envelope_id": "e2", "retry_attempt": 1,
                                "payload": {"team_id": "T_VCD", "event": {"type": "app_mention"}}}) == {"envelope_id": "e2"}


def test_foreign_workspace_is_refused(world):
    ack = responder.handle_command({**cmd("cases"), "team_id": "T_OTHER"})
    assert "another workspace" in ack["text"] and not world.platform_calls


def test_manifest_needs_the_token_and_reports_readiness(client, world):
    from app import auth
    assert client.get("/api/module").status_code == 401
    m = client.get("/api/module", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert m["module"] == "slack" and m["readiness"]["integrations"]["kind"] == "bridge"
    assert m["readiness"]["hub_configured"] is True and set(m["acts_through"]) == {"incident-response", "sabine", "dark-web-monitoring", "vulnerability-management", "managed-services"}


def test_console_login(client, world):
    assert client.get("/", follow_redirects=False).status_code == 302
    client.post("/login", data={"username": "admin", "password": "pw"})
    r = client.get("/")
    assert r.status_code == 200 and "War rooms" in r.text


def test_help_has_no_dashes():
    text = blocks.help_text()
    assert "—" not in text and "–" not in text


def test_first_declare_before_any_feed_run_does_not_flood(world):
    old = world.add_case(client="Harbor Point", pid="plat-hp")
    _room(world)
    ir_posts = [p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"]
    assert len(ir_posts) == 1 and old["number"] not in ir_posts[0]["text"]
    feed.cycle()
    assert len([p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"]) == 1


# ---------------------------------------------------------------- review hardening
def test_a_mention_never_changes_a_case(world):
    case, room = _room(world)
    n_status, n_page = len(world.ir("/status")), len(world.ir("/api/oncall/page"))
    for text in ("<@U_BOT> contained the host yet?", "<@U_BOT> closed it out, thanks", "<@U_BOT> page me when FS01 is imaged"):
        responder.handle_event({"team_id": "T_VCD", "event": {"type": "app_mention", "user": "U_DAN",
                                                              "channel": room.channel_id, "ts": "9.9", "text": text}})
    assert len(world.ir("/status")) == n_status and len(world.ir("/api/oncall/page")) == n_page
    assert len([c for c in world.sabine_calls if c["path"] == "/api/ask"]) == 3
    responder.handle_event({"team_id": "T_VCD", "event": {"type": "app_mention", "user": "U_DAN",
                                                          "channel": room.channel_id, "ts": "9.9", "text": "<@U_BOT> sitrep"}})
    assert world.ir(f"/api/ir-cases/{case['number']}")


def test_lead_must_be_rostered_staff(world):
    case, room = _room(world)
    invites = len(world.slack("conversations.invite"))
    responder.handle_command(cmd("lead <@U_NOBODY>", channel=room.channel_id))
    assert any("not on the platform staff roster" in m for m in _ephemerals(world))
    assert len(world.slack("conversations.invite")) == invites and not world.ir("/details")


def test_link_only_binds_private_unshared_channels(world, monkeypatch):
    case = world.add_case()
    real = world._slack

    def info(chan):
        def handler(req):
            if req.url.path.endswith("conversations.info"):
                world.slack_calls.append(("conversations.info", {}))
                import httpx
                return httpx.Response(200, json={"ok": True, "channel": chan}) if chan else \
                    httpx.Response(200, json={"ok": False, "error": "channel_not_found"})
            return real(req)
        monkeypatch.setattr(world, "_slack", handler)

    for chan, why in (({"id": "C1", "is_private": False, "is_member": True}, "private channels"),
                      ({"id": "C1", "is_private": True, "is_member": True, "is_ext_shared": True}, "shared outside"),
                      (None, "could not read"),
                      ({"id": "C1", "is_private": True, "is_member": False}, "Add me")):
        info(chan)
        world.responses.clear()
        responder.handle_command(cmd(f"link {case['number']}", channel="C1"))
        assert any(why in m for m in _ephemerals(world)), why
        assert SessionLocal().query(WarRoom).count() == 0
    info({"id": "C1", "name": "ir-private", "is_private": True, "is_member": True})
    responder.handle_command(cmd(f"link {case['number']}", channel="C1"))
    assert SessionLocal().query(WarRoom).filter_by(channel_id="C1").one().case_number == case["number"]


def test_privileged_case_keeps_its_title_and_timeline_out_of_slack(world):
    feed.cycle()  # seed
    case = world.add_case()
    case["privileged"] = True
    case["updates"] = [{"at": "2026-10-17T18:05:00+00:00", "actor": "x", "kind": "note", "note": "counsel analysis", "internal_only": True}]
    feed.cycle()
    post = [p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"][-1]
    dump = json.dumps(post)
    assert case["title"] not in dump and "Privileged" in dump
    responder.handle_command(cmd(f"room {case['number']}"))
    room = SessionLocal().query(WarRoom).one()
    n_public = len([p for p in world.slack("chat.postMessage") if p.get("channel") == room.channel_id])
    responder.handle_command(cmd("sitrep", channel=room.channel_id))
    assert len([p for p in world.slack("chat.postMessage") if p.get("channel") == room.channel_id]) == n_public
    assert "counsel analysis" not in json.dumps(world.responses[-1])


def test_stale_roster_allows_reads_but_not_changes(world):
    case, room = _room(world)
    world.platform_up = False
    for m in identity._ROSTER.values():
        m["at"] = m["good_at"] = 0
    world.responses.clear()
    responder.handle_command(cmd("tasks", channel=room.channel_id))
    assert not any("cannot reach" in m for m in _ephemerals(world))
    n = len(world.ir("/updates"))
    responder.handle_command(cmd("note should not land", channel=room.channel_id))
    assert len(world.ir("/updates")) == n and any("more than 15 minutes old" in m for m in _ephemerals(world))


def test_unknown_workspace_is_refused_when_auth_failed(world):
    slack.IDENTITY.update(team_id="", detail="invalid_auth")
    world_auth = world._slack

    def bad_auth(req):
        import httpx
        if req.url.path.endswith("auth.test"):
            return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
        return world_auth(req)
    world._slack = bad_auth
    ack = responder.handle_command(cmd("cases"))
    assert "another workspace" in ack["text"]


def test_oversized_slack_request_is_refused_unread(client, world):
    body = b"x" * (1024 * 1024 + 1)
    assert client.post("/slack/commands", content=body, headers=_sign(body)).status_code == 401


def test_declare_form_needs_the_platform_client_list(world):
    world.clients = []
    ack = responder.handle_command(cmd("declare"))
    assert "cannot load the client list" in ack["text"] and not world.slack("views.open")
    sub = {"type": "view_submission", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"},
           "view": {"callback_id": "declare", "private_metadata": "C1", "state": {"values": {
               "client_name": {"v": {"value": "Typo Credit Unoin"}},
               "severity": {"v": {"selected_option": {"value": "high"}}},
               "desc": {"v": {"value": "x"}}}}}}
    assert responder.handle_interaction(sub)["response_action"] == "errors"
    assert not world.ir("/api/ir-cases/declare")
