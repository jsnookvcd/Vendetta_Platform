"""The external-tool commands: dark web report, Shodan, EDR host lookup and
two-person containment, all through the owning modules on behalf of the person."""
import json

from app import responder
from app.db import AuditLog, Posted, SessionLocal, WarRoom

from conftest import cmd


def _eph(world):
    return [r[1].get("text", "") for r in world.responses]


def _room(world, user="U_DAN"):
    responder.handle_command(cmd("declare critical riverbend: ransom note on FS01", user=user))
    room = SessionLocal().query(WarRoom).one()
    return world.cases[room.case_number], room


def _posts(world, channel):
    return [p for p in world.slack("chat.postMessage") if p.get("channel") == channel]


# ---------------------------------------------------------------- dark web
def test_darkweb_in_a_war_room_posts_summary_and_pdf_and_notes_the_case(world):
    case, room = _room(world)
    responder.handle_command(cmd("darkweb", channel=room.channel_id))
    rep = world.tools("/report")[-1]
    assert rep["path"] == "/api/clients/platform/plat-rb/report" and rep["person"] == "dan@vendettacd.io"
    assert rep["params"]["days"] == "30"
    card = json.dumps(_posts(world, room.channel_id)[-1])
    assert "jsmith@riverbendcu.org" in card and "akira" in card and "Force password resets" in card
    assert world.uploads and world.uploads[-1][1].startswith(b"%PDF")
    done = world.slack("files.completeUploadExternal")[-1]
    assert done["channel_id"] == room.channel_id and done["files"][0]["id"] == "F123"
    assert any(n["body"]["note"].startswith("Dark web report pulled from Slack") for n in world.ir("/updates"))


def test_darkweb_outside_a_room_names_the_client_and_dms_the_pdf(world):
    responder.handle_command(cmd("darkweb harbor 90"))
    rep = world.tools("/report")[-1]
    assert rep["path"] == "/api/clients/platform/plat-hp/report" and rep["params"]["days"] == "90"
    assert world.slack("files.completeUploadExternal")[-1]["channel_id"] == "D_U_DAN"
    assert not world.ir("/updates")


def test_darkweb_needs_a_dark_web_grant(world):
    world.roster["dark-web-monitoring"] = []
    responder.handle_command(cmd("darkweb harbor"))
    assert not world.tools("/report") and any("not on the platform staff roster" in m for m in _eph(world))


# ---------------------------------------------------------------- Shodan
def test_shodan_in_room_with_ad_hoc_target(world):
    case, room = _room(world)
    responder.handle_command(cmd("shodan 34.120.10.10 vpn.riverbendcu.org", channel=room.channel_id))
    call = world.tools("/shodan")[-1]
    assert call["method"] == "POST" and call["path"] == "/api/clients/platform/plat-rb/shodan"
    assert call["body"] == {"targets": "34.120.10.10 vpn.riverbendcu.org"} and call["person"] == "dan@vendettacd.io"
    card = json.dumps(_posts(world, room.channel_id)[-1])
    assert "Remote Desktop (RDP)" in card and "CVE-2024-21762" in card
    assert any("Shodan exposure check from Slack" in n["body"]["note"] for n in world.ir("/updates"))


def test_shodan_outside_room_uses_saved_assets_and_viewer_cannot_run(world):
    responder.handle_command(cmd("shodan riverbend credit"))
    assert world.tools("/shodan")[-1]["body"] == {}
    n = len(world.tools("/shodan"))
    responder.handle_command(cmd("shodan riverbend credit", user="U_VIEW"))
    assert len(world.tools("/shodan")) == n and any("run checks in vulnerability management" in m for m in _eph(world))


# ---------------------------------------------------------------- hosts
def test_host_lookup_shows_status_alerts_and_buttons(world):
    responder.handle_command(cmd("host rb-ws01 riverbend credit", user="U_VIEW"))
    blocks_ = world.responses[-1][1]["blocks"]
    dump = json.dumps(blocks_)
    assert "RB-WS01" in dump and "Ransomware behavior" in dump and "CrowdStrike Falcon" in dump
    ids = [e["action_id"] for b in blocks_ if b["type"] == "actions" for e in b["elements"]]
    assert "host_request" in ids
    assert len([b for b in blocks_ if b["type"] == "divider"]) == 1  # the exact hostname wins over RB-WS010


# ---------------------------------------------------------------- containment, two people
def test_contain_request_then_a_second_person_approves(world):
    case, room = _room(world)
    responder.handle_command(cmd("contain RB-WS01 beaconing to 34.120.10.10", channel=room.channel_id))
    req = world.tools("/api/action-requests")[-1]
    assert req["body"]["action_id"] == "cs_contain" and req["body"]["device_id"] == "dev1"
    assert req["body"]["reason"] == "beaconing to 34.120.10.10" and req["body"]["source_ref"] == case["number"]
    card = _posts(world, room.channel_id)[-1]
    ids = [e["action_id"] for b in card["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert ids == ["host_approve", "host_reject"]
    row = SessionLocal().query(Posted).filter_by(kind="action").one()
    assert row.ts and row.state == "pending"

    click = {"type": "block_actions", "team": {"id": "T_VCD"}, "channel": {"id": room.channel_id},
             "container": {"message_ts": row.ts}, "response_url": "https://hooks.slack.com/actions/z",
             "actions": [{"action_id": "host_approve", "value": row.ref}]}
    # the requester clicks Approve: refused by managed services, nothing runs
    responder.handle_interaction({**click, "user": {"id": "U_DAN"}})
    assert world.requests[row.ref]["status"] == "pending"
    assert any("second person" in m for m in _eph(world))
    # a viewer cannot even ask
    n = len(world.tools("/decide"))
    responder.handle_interaction({**click, "user": {"id": "U_VIEW"}})
    assert len(world.tools("/decide")) == n
    # an approver clicks
    responder.handle_interaction({**click, "user": {"id": "U_LEADER"}})
    dec = world.tools("/decide")[-1]
    assert dec["person"] == "kenedi@vendettacd.io" and dec["body"]["approve"] is True
    assert world.requests[row.ref]["status"] == "done"
    upd = world.slack("chat.update")[-1]
    assert upd["ts"] == row.ts and "Approved by Kenedi Crossley and carried out" in upd["text"]
    notes = [n["body"]["note"] for n in world.ir("/updates")]
    assert any("Network contain on RB-WS01" in n and "requested from Slack" in n for n in notes)
    assert any("carried out" in n for n in notes)
    # a late second click is answered with the current state
    responder.handle_interaction({**click, "user": {"id": "U_JORDAN"}})
    assert "already done" in world.slack("chat.update")[-1]["text"]


def test_release_runs_at_once_and_readonly_refuses(world):
    case, room = _room(world)
    responder.handle_command(cmd("release RB-WS01", channel=room.channel_id))
    assert world.tools("/api/action-requests")[-1]["body"]["action_id"] == "cs_lift"
    assert "done" in _posts(world, room.channel_id)[-1]["text"]
    world.ms_readonly = True
    n = len(world.tools("/api/action-requests"))
    responder.handle_command(cmd("contain RB-WS01 x", channel=room.channel_id))
    assert len(world.tools("/api/action-requests")) == n and any("read-only" in m for m in _eph(world))


def test_contain_outside_room_needs_client_and_ambiguity_asks(world):
    responder.handle_command(cmd("contain RB-WS01 riverbend credit: lateral movement"))
    req = world.tools("/api/action-requests")[-1]
    assert req["body"]["reason"] == "lateral movement" and req["body"]["source_ref"] == ""
    n = len(world.tools("/api/action-requests"))
    responder.handle_command(cmd("contain RB-WS0 riverbend credit: x"))
    assert len(world.tools("/api/action-requests")) == n
    assert "Pick a host" in world.responses[-1][1]["text"]


def test_host_button_files_the_request(world):
    payload = {"type": "block_actions", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"}, "channel": {"id": "C_SOC"},
               "response_url": "https://hooks.slack.com/actions/q",
               "actions": [{"action_id": "host_request", "value": "plat-rb|dev1|cs_contain"}]}
    responder.handle_interaction(payload)
    assert world.tools("/api/action-requests")[-1]["body"]["device_id"] == "dev1"
    assert SessionLocal().query(AuditLog).filter_by(action="tool.request.pending").count() == 1


def test_mention_can_look_but_never_contain(world):
    case, room = _room(world)
    for text in ("<@U_BOT> contain RB-WS01 now", "<@U_BOT> release RB-WS01"):
        responder.handle_event({"team_id": "T_VCD", "event": {"type": "app_mention", "user": "U_DAN",
                                                              "channel": room.channel_id, "ts": "1.1", "text": text}})
    assert not world.tools("/api/action-requests")
    responder.handle_event({"team_id": "T_VCD", "event": {"type": "app_mention", "user": "U_DAN",
                                                          "channel": room.channel_id, "ts": "1.1", "text": "<@U_BOT> host RB-WS01"}})
    assert world.tools("/api/devices")


def test_upload_refuses_a_foreign_upload_url(world, monkeypatch):
    from app import slack
    real = world._slack

    def evil(req):
        import httpx
        if req.url.path.endswith("files.getUploadURLExternal"):
            return httpx.Response(200, json={"ok": True, "upload_url": "https://evil.example/u", "file_id": "F1"})
        return real(req)
    monkeypatch.setattr(world, "_slack", evil)
    assert slack.upload("C1", "x.pdf", b"x") is False and not world.uploads


# ---------------------------------------------------------------- review hardening
def test_another_clients_data_stays_private_and_off_the_case(world):
    case, room = _room(world)
    before_posts, before_notes = len(_posts(world, room.channel_id)), len(world.ir("/updates"))
    responder.handle_command(cmd("darkweb harbor", channel=room.channel_id))
    assert world.tools("/report")[-1]["path"] == "/api/clients/platform/plat-hp/report"
    assert len(_posts(world, room.channel_id)) == before_posts            # nothing public in Riverbend's room
    assert world.slack("files.completeUploadExternal")[-1]["channel_id"] == "D_U_DAN"
    assert len(world.ir("/updates")) == before_notes                       # nothing on Riverbend's case


def test_shared_or_privileged_room_gets_private_results(world):
    case, room = _room(world)
    world.shared_channels.add(room.channel_id)
    n = len(_posts(world, room.channel_id))
    responder.handle_command(cmd("darkweb", channel=room.channel_id))
    assert len(_posts(world, room.channel_id)) == n
    world.shared_channels.clear()
    case["privileged"] = True
    responder.handle_command(cmd("shodan", channel=room.channel_id))
    assert len(_posts(world, room.channel_id)) == n
    assert any("Shodan exposure check" in u["body"]["note"] for u in world.ir("/updates"))  # still on its own case


def test_outside_room_contain_goes_to_the_approvals_channel(world):
    responder.handle_command(cmd("contain RB-WS01 riverbend credit: lateral movement"))
    card = [p for p in world.slack("chat.postMessage") if p.get("channel") == "C_IR"][-1]
    ids = [e["action_id"] for b in card["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert ids == ["host_approve", "host_reject"]
    assert any("waiting for approval in <#C_IR>" in m for m in _eph(world))


def test_no_approvals_channel_means_war_room_only(world, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "slack_ir_channel", "")
    monkeypatch.setattr(settings, "slack_approvals_channel", "")
    responder.handle_command(cmd("contain RB-WS01 riverbend credit: x"))
    assert not world.tools("/api/action-requests") and any("war room" in m for m in _eph(world))


def test_forged_button_action_is_refused(world):
    payload = {"type": "block_actions", "team": {"id": "T_VCD"}, "user": {"id": "U_DAN"}, "channel": {"id": "C_SOC"},
               "response_url": "https://hooks.slack.com/actions/q",
               "actions": [{"action_id": "host_request", "value": "plat-rb|dev1|s1_kill"}]}
    responder.handle_interaction(payload)
    assert not world.tools("/api/action-requests")
    payload["actions"][0]["value"] = "plat-hp|dev1|cs_contain"   # dev1 is Riverbend's
    responder.handle_interaction(payload)
    assert not world.tools("/api/action-requests")
