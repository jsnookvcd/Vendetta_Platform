"""The delivery method: templates, client milestones, change control, capacity,
portfolio metrics, alerts, closeout and invoicing."""
import datetime as dt
import json

import httpx
from conftest import Mcp, add_user, connect_claude

from app import alerts, capacity, metrics, milestones, service, templates_lib
from app.db import Alert, Card, CardEvent, ChangeRequest, Engagement, SessionLocal, Template, utcnow

TODAY = dt.date.today()


def _pm(client, email="pm@vendettacd.io", role="analyst"):
    add_user(email, role)
    return Mcp(client, connect_claude(client, email)["access_token"])


# ---------------------------------------------------------------- templates
def test_builtin_templates_seeded(client):
    db = SessionLocal()
    keys = {t.key for t in db.query(Template).all()}
    assert {"bec", "ransomware", "malware-analysis", "ir-general", "tabletop", "vciso-onboarding", "pentest",
            "pre-ransomware"} <= keys


def test_open_from_template_lays_down_the_method(client):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Wire fraud BEC", client="North Central", template="bec",
             lead="dan@vendettacd.io", starts_on=TODAY.isoformat())
    assert e["type"] == "bec" and e["budget_hours"] == 40 and e["baseline_budget_hours"] == 40
    assert e["ends_on"] == (TODAY + dt.timedelta(days=14)).isoformat()
    assert len(e["milestones"]) == 4 and e["closeout"] == "0/7"
    tasks = m.ok("list_tasks", engagement=e["code"])["tasks"]
    assert len(tasks) == 13
    by = {t["title"]: t for t in tasks}
    kickoff = by["Kickoff call: scope, counsel, privilege and insurer"]
    assert kickoff["assignee"] == "pm@vendettacd.io" and kickoff["due_on"] == TODAY.isoformat()
    ual = by["Collect UAL, sign-in logs and message trace"]
    assert ual["assignee"] == "dan@vendettacd.io" and ual["due_on"] == (TODAY + dt.timedelta(days=1)).isoformat()
    assert ual["labels"] == ["Forensics and Analysis"] and ual["checklist"] == "0/4"
    full = m.ok("get_task", task=str(ual["ref"]))
    assert full["estimate_hours"] == 4


def test_save_engagement_as_template_and_apply_it(client):
    m = _pm(client)
    e = m.ok("create_engagement", practice="proserv", name="Board tabletop", starts_on=TODAY.isoformat(),
             ends_on=(TODAY + dt.timedelta(days=20)).isoformat(), budget_hours=24)
    m.ok("create_task", engagement=e["code"], title="Design scenario", assignee="me",
         due_on=(TODAY + dt.timedelta(days=5)).isoformat(), estimate_hours=6)
    m.ok("manage_milestone", engagement=e["code"], action="add", title="Exercise held",
         due_on=(TODAY + dt.timedelta(days=15)).isoformat())
    t = m.ok("save_template", key="board-ttx", name="Board tabletop", from_engagement=e["code"])
    assert t["tasks"][0]["owner"] == "pm" and t["tasks"][0]["offset_days"] == 5
    assert t["milestones"][0]["offset_days"] == 15 and t["duration_days"] == 20
    e2 = m.ok("create_engagement", practice="proserv", name="Second tabletop")
    res = m.ok("apply_template", engagement=e2["code"], template="board-ttx", start="2026-12-01")
    assert res["tasks_added"] == 1 and res["ends_on"] == "2026-12-21"
    wrong = m.call("apply_template", engagement=e2["code"], template="bec")
    assert wrong["isError"] and "is for ir" in wrong["content"][0]["text"]


def test_template_editing_validates(admin):
    r = admin.post("/templates", data={"key": "bad", "name": "Bad", "practice": "ir", "tasks": "not json"},
                   follow_redirects=False)
    assert "err=" in r.headers["location"]
    admin.post("/templates", data={"key": "quick", "name": "Quick look", "practice": "ir", "active": "true",
                                   "tasks": json.dumps([{"title": "Triage", "owner": "lead", "offset_days": 0}]),
                                   "milestones": "[]", "phase_days": json.dumps({"Intake": 1}),
                                   "closeout": "Report sent\nInvoice drafted"})
    t = templates_lib.find(SessionLocal(), "quick")
    assert t.tasks[0]["title"] == "Triage" and t.closeout == ["Report sent", "Invoice drafted"]
    assert admin.get("/templates").status_code == 200 and admin.get("/templates/quick").status_code == 200


# ---------------------------------------------------------------- milestones to the client
def test_milestones_publish_to_hub_and_osp(client, monkeypatch):
    from app.config import settings
    sent = []

    def handler(req: httpx.Request):
        sent.append((str(req.url), req.headers.get("authorization"), json.loads(req.content)))
        return httpx.Response(200, json={"ok": True})
    milestones.TRANSPORT = httpx.MockTransport(handler)
    monkeypatch.setattr(settings, "platform_hub_url", "http://incident-response:8000")
    monkeypatch.setattr(settings, "platform_hub_token", "hubtok")
    monkeypatch.setattr(settings, "osp_url", "http://professional-services:8000")
    monkeypatch.setattr(settings, "osp_token", "osptok")
    try:
        m = _pm(client)
        e = m.ok("create_engagement", practice="ir", name="Ransomware", template="ransomware",
                 platform_ref="VCD-IR-2026-781")
        url, tok, body = sent[-1]
        assert url == "http://incident-response:8000/api/ir-cases/VCD-IR-2026-781/milestones" and tok == "Bearer hubtok"
        assert len(body["milestones"]) == 6 and body["engagement_code"] == e["code"]
        m.ok("manage_milestone", engagement=e["code"], action="add", title="Internal check", client_visible=False)
        assert len(sent[-1][2]["milestones"]) == 6  # internal milestones never leave the module
        r = m.ok("manage_milestone", engagement=e["code"], action="update", milestone="Environment contained",
                 status="done")
        assert r["client_portal"]["published"] is True
        done = [x for x in sent[-1][2]["milestones"] if x["status"] == "done"]
        assert done[0]["title"] == "Environment contained" and done[0]["completed_on"] == TODAY.isoformat()
        p = m.ok("create_engagement", practice="proserv", name="Tabletop", template="tabletop", platform_ref="osp-e1")
        assert sent[-1][0] == "http://professional-services:8000/api/engagements/osp-e1/milestones"
        assert p["client_publishing"]["status"] == "ok"
        none = m.ok("create_engagement", practice="ir", name="No ref")
        res = m.ok("manage_milestone", engagement=none["code"], action="publish")
        assert res["client_portal"]["published"] is False and "platform reference" in res["client_portal"]["reason"]
    finally:
        milestones.TRANSPORT = None


def test_publish_failure_is_recorded_and_alerted(client, monkeypatch):
    from app.config import settings
    milestones.TRANSPORT = httpx.MockTransport(lambda req: httpx.Response(404))
    monkeypatch.setattr(settings, "platform_hub_url", "http://incident-response:8000")
    try:
        m = _pm(client)
        e = m.ok("create_engagement", practice="ir", name="Bad ref", template="bec", platform_ref="VCD-IR-1999-1")
        assert e["client_publishing"]["status"] == "failed" and "not found" in e["client_publishing"]["detail"]
        alerts.run_once(SessionLocal(), with_burn=False)
        assert any(a["kind"] == "publish_failed" for a in m.ok("list_alerts", scope="all")["alerts"])
    finally:
        milestones.TRANSPORT = None


# ---------------------------------------------------------------- change control
def test_change_request_needs_a_second_person_and_moves_scope(client):
    pm = _pm(client)
    e = pm.ok("create_engagement", practice="ir", name="Scope grows", budget_hours=40,
              ends_on=(TODAY + dt.timedelta(days=10)).isoformat())
    cr = pm.ok("request_change", engagement=e["code"], title="Add three file servers", hours_delta=16, days_delta=5,
               reason="scope_discovery", client_approval="CIO by email")
    assert cr["number"] == "CR-1" and cr["status"] == "requested"
    own = pm.call("decide_change", engagement=e["code"], change="CR-1", decision="approve")
    assert own["isError"] and "second person" in own["content"][0]["text"]
    dan = _pm(client, "dan@vendettacd.io")
    ok = dan.ok("decide_change", engagement=e["code"], change="1", decision="approve", note="agreed on call")
    assert ok["status"] == "approved" and ok["scope"]["current_hours"] == 56 and ok["scope"]["baseline_hours"] == 40
    assert ok["scope"]["current_ends_on"] == (TODAY + dt.timedelta(days=15)).isoformat()
    again = dan.call("decide_change", engagement=e["code"], change="CR-1", decision="reject")
    assert again["isError"] and "already approved" in again["content"][0]["text"]
    cr2 = pm.ok("request_change", engagement=e["code"], title="Extra readout", hours_delta=2)
    pm.ok("decide_change", engagement=e["code"], change=cr2["number"], decision="withdraw")
    lst = pm.ok("list_changes", engagement=e["code"])
    assert [c["status"] for c in lst["changes"]] == ["withdrawn", "approved"]
    bad = pm.call("request_change", engagement=e["code"], title="Nothing")
    assert bad["isError"] and "must move" in bad["content"][0]["text"]


# ---------------------------------------------------------------- capacity
def test_capacity_by_week_with_defaults_and_overload(client):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Load", budget_hours=80)
    m.ok("create_task", engagement=e["code"], title="Big", assignee="me", due_on=TODAY.isoformat(), estimate_hours=30)
    m.ok("create_task", engagement=e["code"], title="Unestimated", assignee="me", due_on=TODAY.isoformat())
    m.ok("create_task", engagement=e["code"], title="Next week", assignee="dan@vendettacd.io",
         due_on=(TODAY + dt.timedelta(days=7)).isoformat(), estimate_hours=8, checklist=["a", "b"])
    t = m.ok("update_task", task=str(m.ok("list_tasks", assignee="dan@vendettacd.io")["tasks"][0]["ref"]),
             checklist_check=[1])
    m.ok("create_task", engagement=e["code"], title="Someday", assignee="me", estimate_hours=5)
    db = SessionLocal()
    capacity.set_capacity(db, "pm@vendettacd.io", weekly_hours=30)
    db.commit()
    data = m.ok("team_capacity", weeks=3)
    pm = next(p for p in data["people"] if p["email"] == "pm@vendettacd.io")
    assert pm["weeks"][0]["planned_hours"] == 32.0 and pm["weeks"][0]["over"] and pm["capacity_hours"] == 30
    assert pm["unestimated_tasks"] == 1 and pm["unscheduled_hours"] == 5
    dan = next(p for p in data["people"] if p["email"] == "dan@vendettacd.io")
    assert dan["weeks"][1]["planned_hours"] == 4.0  # half the checklist is done
    assert "pm@vendettacd.io" in data["overloaded_next_2_weeks"]
    fit = m.ok("team_capacity", practice="ir", hours=20, weeks=2)
    assert fit["best_placed"][0]["email"] == "dan@vendettacd.io" and "fits" in fit
    assert t["checklist"] == "1/2"
    refused = m.call("set_capacity", person="dan@vendettacd.io", weekly_hours=20)
    assert refused["isError"] and "admin" in refused["content"][0]["text"]


# ---------------------------------------------------------------- metrics
def test_key_dates_phases_and_portfolio(client):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Measured", template="bec", budget_hours=None)
    db = SessionLocal()
    eng = service.find_engagement(db, e["code"])
    card = service.practice_card(db, eng)
    # Backdate the opening so the phase durations are measurable.
    opened = utcnow() - dt.timedelta(days=6)
    eng.created_at = opened
    db.query(CardEvent).filter_by(card_id=card.id, kind="created").update({"at": opened})
    db.commit()
    m.ok("move_engagement", engagement=e["code"], phase="Scoping and Containment")
    db = SessionLocal()
    ev = db.query(CardEvent).filter_by(card_id=card.id, kind="moved").one()
    ev.at = opened + dt.timedelta(days=1)
    db.commit()
    m.ok("move_engagement", engagement=e["code"], phase="Forensics and Analysis")
    db = SessionLocal()
    eng = service.find_engagement(db, e["code"])
    assert eng.contained_at is not None and eng.reported_at is None
    pd = metrics.phase_days(db, eng)
    assert round(pd["Intake"]) == 1 and round(pd["Scoping and Containment"]) == 5
    m.ok("move_engagement", engagement=e["code"], phase="Closeout and Billing")
    one = m.ok("portfolio_metrics", engagement=e["code"])
    assert one["time_to_contain_hours"] >= 143 and one["time_to_report_days"] >= 5.9 and one["type"] == "bec"
    port = m.ok("portfolio_metrics", days=30, include_engagements=True)
    assert port["totals"]["engagements"] == 1 and "bec" in port["by_type"]
    phases = port["totals"]["avg_days_per_phase"]
    assert phases["Scoping and Containment"]["target"] == 2


def test_metrics_page_renders(admin):
    admin.post("/engagements", data={"practice": "proserv", "name": "Pentest", "template": "pentest"})
    assert "median time to contain" in admin.get("/metrics").text
    assert admin.get("/capacity").status_code == 200


# ---------------------------------------------------------------- alerts
def test_alerts_raise_dedupe_ack_and_clear(client):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Alerting", ends_on=(TODAY - dt.timedelta(days=1)).isoformat())
    t = m.ok("create_task", engagement=e["code"], title="Late", assignee="me",
             due_on=(TODAY - dt.timedelta(days=5)).isoformat())
    b = m.ok("create_task", engagement=e["code"], title="Stuck", assignee="me", column="Blocked")
    m.ok("manage_milestone", engagement=e["code"], action="add", title="Contained",
         due_on=(TODAY - dt.timedelta(days=2)).isoformat())
    m.ok("request_change", engagement=e["code"], title="More hours", hours_delta=4)
    db = SessionLocal()
    card = db.query(Card).filter_by(title="Stuck").one()
    db.query(CardEvent).filter_by(card_id=card.id).update({"at": utcnow() - dt.timedelta(days=4)})
    db.query(ChangeRequest).update({"requested_at": utcnow() - dt.timedelta(days=3)})
    db.commit()
    res = alerts.run_once(SessionLocal(), with_burn=False)
    assert res["new"] >= 5
    kinds = {a["kind"] for a in m.ok("list_alerts")["alerts"]}
    assert {"task_overdue", "task_blocked", "end_overdue", "milestone_overdue"} <= kinds
    allk = {a["kind"] for a in m.ok("list_alerts", scope="all")["alerts"]}
    assert "change_pending" in allk  # owner is not the requester, so it is not "mine"
    again = alerts.run_once(SessionLocal(), with_burn=False)
    assert again["new"] == 0  # one alert per standing condition
    late_key = f"task_overdue:{t['id']}"
    assert m.ok("acknowledge_alert", key=late_key)["acked_by"] == "pm@vendettacd.io"
    m.ok("move_task", task=str(t["ref"]), column="Done")
    m.ok("move_task", task=str(b["ref"]), column="In Progress")
    cleared = alerts.run_once(SessionLocal(), with_burn=False)
    assert cleared["resolved"] >= 2
    assert SessionLocal().get(Alert, late_key).resolved_at is not None
    api = client.get("/api/alerts", headers={"Authorization": f"Bearer {m.token}"}).json()["alerts"]
    assert all(a["engagement"] == e["code"] for a in api if a["engagement_id"])


def test_burn_and_scope_creep_from_harvest(client, fake_harvest):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Burning", harvest_project_id="501", budget_hours=40)
    fake_harvest.project_hours[501] = 34.0
    alerts.run_once(SessionLocal())
    kinds = {a["kind"] for a in m.ok("list_alerts")["alerts"]}
    assert "burn_warn" in kinds and "scope_creep" not in kinds
    fake_harvest.project_hours[501] = 44.0
    alerts.run_once(SessionLocal())
    kinds = {a["kind"] for a in m.ok("list_alerts")["alerts"]}
    assert {"burn_over", "scope_creep"} <= kinds and "burn_warn" not in kinds
    m.ok("request_change", engagement=e["code"], title="Extend analysis", hours_delta=10)
    alerts.run_once(SessionLocal())
    assert "scope_creep" not in {a["kind"] for a in m.ok("list_alerts")["alerts"]}


def test_new_high_alerts_post_to_teams(client, monkeypatch):
    from app.config import alert_settings
    posted = []
    alerts.TRANSPORT = httpx.MockTransport(lambda req: posted.append(json.loads(req.content)) or httpx.Response(200))
    monkeypatch.setattr(alert_settings, "teams_webhook_url", "https://example.invalid/hook")
    try:
        m = _pm(client)
        e = m.ok("create_engagement", practice="ir", name="Teams")
        m.ok("create_task", engagement=e["code"], title="Very late", priority="urgent",
             due_on=(TODAY - dt.timedelta(days=1)).isoformat())
        alerts.run_once(SessionLocal(), with_burn=False)
        assert len(posted) == 1 and "Very late" in json.dumps(posted[0])
        alerts.run_once(SessionLocal(), with_burn=False)
        assert len(posted) == 1
    finally:
        alerts.TRANSPORT = None


# ---------------------------------------------------------------- closeout and invoicing
def test_closeout_and_draft_invoice(client, fake_harvest):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Invoice me", harvest_project_id="501",
             starts_on="2026-10-01")
    view = m.ok("closeout", engagement=e["code"])
    assert view["total"] == 7 and view["done"] == 0
    m.ok("closeout", engagement=e["code"], action="check", item="final report")
    m.ok("closeout", engagement=e["code"], action="add", item="Destroy sandbox VM")
    un = m.ok("uninvoiced_time", engagement=e["code"])
    assert un["uninvoiced_hours"] == 12.5 and un["uninvoiced_amount"] == 3125.0
    inv = m.ok("draft_invoice", engagement=e["code"], end=TODAY.isoformat(), summary_type="task")
    assert inv["state"] == "draft" and "does not send" in inv["next"]
    body = fake_harvest.invoices[-1]
    assert body["client_id"] == 77 and body["line_items_import"]["project_ids"] == [501]
    assert body["line_items_import"]["time"] == {"summary_type": "task", "from": "2026-10-01", "to": TODAY.isoformat()}
    after = m.ok("closeout", engagement=e["code"])
    assert {i["text"]: i["done"] for i in after["items"]}["Invoice drafted"] is True
    assert after["done"] == 2 and after["invoices"][0]["number"] == "INV-1"
    fixed = m.ok("draft_invoice", engagement=e["code"], fixed_amount=5000)
    assert fake_harvest.invoices[-1]["line_items"][0]["unit_price"] == 5000.0 and fixed["state"] == "draft"
    dan = _pm(client, "dan@vendettacd.io")
    no = dan.call("draft_invoice", engagement=e["code"])
    assert no["isError"] and "PM or an admin" in no["content"][0]["text"]
    fake_harvest.uninvoiced.clear()
    empty = m.call("draft_invoice", engagement=e["code"])
    assert empty["isError"] and "nothing uninvoiced" in empty["content"][0]["text"]


def test_viewer_reads_closeout_and_metrics_but_cannot_change(client):
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Viewable")
    v = _pm(client, "viewer@vendettacd.io", "viewer")
    names = {t["name"] for t in v.rpc("tools/list").json()["result"]["tools"]}
    assert {"closeout", "portfolio_metrics", "team_capacity", "list_alerts"} <= names
    assert not {"request_change", "draft_invoice", "save_template", "manage_milestone"} & names
    assert v.ok("closeout", engagement=e["code"])["total"] == 7
    no = v.call("closeout", engagement=e["code"], action="check", item="1")
    assert no["isError"]


def test_engagement_page_renders_every_section(admin):
    r = admin.post("/engagements", data={"practice": "ir", "name": "Full page", "template": "ransomware"},
                   follow_redirects=False)
    eid = r.headers["location"].split("/engagements/")[1].split("?")[0]
    admin.post(f"/engagements/{eid}/changes", data={"title": "More", "hours_delta": "8"})
    admin.post(f"/engagements/{eid}/milestones", data={"action": "add", "title": "Extra", "client_visible": "true"})
    page = admin.get(f"/engagements/{eid}").text
    for s in ("Milestones", "Scope and change control", "CR-1", "Closeout and invoicing", "Environment contained",
              "Apply a template"):
        assert s in page, s
    db = SessionLocal()
    e = db.get(Engagement, eid)
    admin.post(f"/engagements/{eid}/closeout", data={"action": "check", "item": "1"})
    assert SessionLocal().get(Engagement, eid).closeout[0]["done"] is True and e.engagement_type == "ransomware"
    assert admin.get("/alerts?scope=all").status_code == 200


def test_digest_emails_each_owner_their_alerts(client, fake_graph, monkeypatch):
    from app.config import alert_settings
    monkeypatch.setattr(alert_settings, "mail_from", "pm-alerts@vendettacd.io")
    m = _pm(client)
    e = m.ok("create_engagement", practice="ir", name="Digest")
    m.ok("create_task", engagement=e["code"], title="Late one", assignee="me",
         due_on=(TODAY - dt.timedelta(days=2)).isoformat())
    alerts.run_once(SessionLocal(), with_burn=False)
    res = alerts.send_digests(SessionLocal())
    assert res["sent"] == 1
    path, body = fake_graph.mail[0]
    assert path.endswith("/users/pm-alerts@vendettacd.io/sendMail")
    assert body["message"]["toRecipients"][0]["emailAddress"]["address"] == "pm@vendettacd.io"
    assert "Late one" in body["message"]["body"]["content"]
