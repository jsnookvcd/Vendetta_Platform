"""SABINE runs the business: paging on-call past the client's commitment, the
Security Journey (suggest and progress), the monthly posture review and client
outreach as drafts a person approves on the platform, and suppressions proposed
from decision memory. Every rule against the mocked world in conftest."""
import ast
import datetime as dt
import json
import pathlib

import httpx

from app import brain, ledger, metrics, narrative, reach, skills
from app.config import settings
from app.db import Brief, Proposal, SessionLocal, utcnow

from conftest import DIRECTORY, NOW, OLD, _finding, _investigation

CONCIERGE = pathlib.Path(__file__).resolve().parent.parent / "app" / "concierge.py"


def _props(db, action=None):
    q = db.query(Proposal)
    if action:
        q = q.filter_by(action=action)
    return {p.key: p for p in q.all()}


def test_every_concierge_rule_names_a_catalog_skill_with_an_executor():
    tree = ast.parse(CONCIERGE.read_text())
    actions = {n.args[1].value for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "propose"
               and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)}
    want = {"page_oncall", "suggest_suppression", "journey_suggest", "journey_progress", "posture_review", "client_outreach",
            "engagement_budget_burn", "capacity_overload", "renewal_upcoming", "won_not_onboarded"}
    assert want - {"client_outreach"} <= actions and want <= set(skills.REGISTRY)
    spec = {s.key: (s.domain, s.module, s.risk, s.default, s.executor) for s in skills.REGISTRY.values()}
    assert spec["page_oncall"] == ("soc", "incident-response", "low", "auto", "page_oncall")
    assert spec["suggest_suppression"] == ("soc", "mdr", "medium", "propose", "suggest_suppression")
    for k in ("journey_suggest", "journey_progress", "posture_review", "client_outreach"):
        assert spec[k][:4] == ("services", "platform", "low", "auto"), k
    for k in ("engagement_budget_burn", "capacity_overload", "renewal_upcoming", "won_not_onboarded"):
        assert spec[k] == ("services", "sabine", "low", "auto", "raise_work_item"), k
        assert not skills.get(k).client_visible
    assert not skills.get("posture_review").client_visible and not skills.get("client_outreach").client_visible


# ---------------------------------------------------------------- page_oncall
def test_page_oncall_past_the_commitment_through_the_ir_hub(world):
    db = SessionLocal()
    brain.cycle(db)
    pages = _props(db, "page_oncall")
    # the MDR investigation (40m) and the managed-services critical (120m) against Riverbend's 10-minute commitment
    assert set(pages) == {"page_oncall:mdr:i1", "page_oncall:managed-services:al1"}
    p = pages["page_oncall:mdr:i1"]
    assert p.status == "executed" and p.autonomy == "auto" and p.risk == "low"
    assert p.facts["ack_minutes"] == 10 and p.facts["commitment_source"] == "advanced commitment" and p.facts["age_minutes"] >= 39
    assert p.result["sent"] == {"teams": "sent"} and p.result["detail"] == "paged via teams"
    body = next(b for b in world.pages if b["source_ref"] == "mdr:i1")
    assert set(body) == {"title", "body", "link", "severity", "platform_client_id", "client", "source_module", "source_ref"}
    assert body["title"].startswith("Critical MDR investigation unacknowledged") and "Riverbend Credit Union" in body["title"]
    assert body["link"] == "https://mdr.example/investigations/i1" and body["severity"] == "critical" and body["source_module"] == "mdr"
    assert ("incident-response", "POST", "/api/oncall/page", "Bearer irtok", "sabine") in world.calls
    # al3: the copilot calls it a false positive, so it is queued to confirm instead of paged
    assert "page_oncall:managed-services:al3" not in pages
    # the second cycle inside the hour pages nobody again
    n = len(world.pages)
    brain.cycle(db)
    assert len(world.pages) == n and db.query(Proposal).filter_by(action="page_oncall").count() == 2
    # an hour later, still unacknowledged: one more page
    p = db.get(Proposal, p.id)
    p.executed_at = utcnow() - dt.timedelta(minutes=61)
    db.commit()
    brain.cycle(db)
    assert len(world.pages) == n + 1 and db.query(Proposal).filter_by(key="page_oncall:mdr:i1").count() == 2
    assert ledger.verify(db)["ok"]


def test_page_oncall_respects_ack_case_and_fallback(world):
    db = SessionLocal()
    world.findings["mdr"][0]["acknowledged_at"] = NOW.isoformat()  # acknowledged: no page
    world.findings["managed-services"][0]["subject"]["case_ref"] = "VCD-IR-2026-801"  # in a case: the hub paged
    brain.cycle(db)
    assert not _props(db, "page_oncall")
    # a client with no commitments falls back to CRITICAL_ACK_MINUTES (15)
    world.clients[0].pop("commitments")
    world.findings["mdr"] = [_investigation("i2", "critical", "Ransomware behavior on WS03", "MDR-2026-0011",
                                            (NOW - dt.timedelta(minutes=12)).isoformat(), matched="WS03")]
    brain.cycle(db)
    assert "page_oncall:mdr:i2" not in _props(db, "page_oncall")
    world.findings["mdr"][0]["opened_at"] = (NOW - dt.timedelta(minutes=20)).isoformat()
    brain.cycle(db)
    p = _props(db, "page_oncall")["page_oncall:mdr:i2"]
    assert p.facts["ack_minutes"] == settings.critical_ack_minutes == 15 and p.facts["commitment_source"] == "default"


def test_page_with_no_channel_still_records_honestly(world):
    world.page_sent = {}
    db = SessionLocal()
    brain.cycle(db)
    p = _props(db, "page_oncall")["page_oncall:mdr:i1"]
    assert p.status == "executed" and p.result["sent"] == {} and "nothing was sent" in p.result["detail"]


# ---------------------------------------------------------------- the Security Journey
def test_journey_suggest_raises_proposed_items_once(world):
    db = SessionLocal()
    brain.cycle(db)
    refs = {i["source_ref"]: i for pid in world.journey for i in world.journey[pid]}
    # overdue remediation (Harbor Point), exposed credentials (Riverbend), no detection service (Harbor Point)
    assert {"overdue:plat-hp:high", "gap:plat-rb:credentials", "gap:plat-hp:detection"} <= set(refs)
    item = refs["overdue:plat-hp:high"]
    assert item["status"] == "proposed" and item["source"] == "sabine" and item["area"] == "vulnerability" and item["due_on"]
    assert refs["gap:plat-rb:credentials"]["area"] == "identity"
    p = _props(db, "journey_suggest")["journey_suggest:overdue:plat-hp:high"]
    assert p.status == "executed" and p.result["created"] is True and p.facts["evidence"] == "overdue remediation"
    posts = [c for c in world.calls if c[1] == "POST" and c[2].endswith("/journey")]
    brain.cycle(db)
    assert [c for c in world.calls if c[1] == "POST" and c[2].endswith("/journey")] == posts  # on the journey: not raised again
    # a declined item stays declined; SABINE never re-proposes it
    refs["gap:plat-hp:detection"]["status"] = "declined"
    db.query(Proposal).filter_by(key="journey_suggest:gap:plat-hp:detection").update({"executed_at": utcnow() - dt.timedelta(days=40)})
    db.commit()
    brain.cycle(db)
    assert db.query(Proposal).filter_by(key="journey_suggest:gap:plat-hp:detection").count() == 1


def test_journey_recurring_pattern_and_pentest_class(world, monkeypatch):
    world.findings["managed-services"] += [
        _finding("managed-services", f"r{n}", "medium", f"USB storage mounted on WS1{n}", matched=f"WS1{n}") for n in range(3)]
    world.findings["penetration-testing"] = [
        _finding("penetration-testing", "pt1", "high", "Stored XSS in portal", pid="plat-hp", client="Harbor Point", category="Web application")]
    monkeypatch.setattr(settings, "module_directory", json.dumps(
        {**DIRECTORY, "penetration-testing": {"base_url": "http://penetration-testing:8000", "token": "pt", "public_url": ""}}))
    db = SessionLocal()
    brain.cycle(db)
    refs = {i["source_ref"]: i for pid in world.journey for i in world.journey[pid]}
    rec = next(v for k, v in refs.items() if k.startswith("recurring:plat-rb:managed-services:"))
    assert rec["title"].endswith("findings: USB storage mounted on") and rec["area"] == "endpoint" and rec["status"] == "proposed"
    assert refs["pentest:plat-hp:web-application"]["title"] == "Remediate the Web application class of penetration test findings"


def test_journey_progress_when_evidence_resolves(world):
    db = SessionLocal()
    planned = world.journey_item("plat-hp", "Bring high vulnerability remediation inside the 30-day SLA", status="planned",
                                 source_ref="overdue:plat-hp:high")
    proposed = world.journey_item("plat-rb", "Enforce MFA everywhere and rotate exposed credentials", status="proposed",
                                  source_ref="gap:plat-rb:credentials", source="sabine")
    brain.cycle(db)
    assert planned["status"] == "planned"  # evidence still there
    # the module is down: SABINE never concludes "resolved" from silence
    world.findings["vulnerability-management"] = []
    real = world.handler

    def down(req):
        if req.url.host == "vulnerability-management":
            raise httpx.ConnectError("down")
        return real(req)
    reach.set_transport(httpx.MockTransport(down))
    brain.cycle(db)
    assert planned["status"] == "planned" and not _props(db, "journey_progress")
    # back up and the overdue finding is gone: done, through the platform's progress endpoint
    reach.set_transport(httpx.MockTransport(real))
    world.findings["dark-web-monitoring"] = []  # the credential evidence is gone too, but that item is only proposed
    brain.cycle(db)
    p = _props(db, "journey_progress")[f"journey_progress:{planned['id']}:done"]
    assert p.status == "executed" and planned["status"] == "done" and "resolved" in planned["note"]
    assert proposed["status"] == "proposed"  # only a person accepts a proposal
    assert not any(c[2].endswith(f"/journey/{proposed['id']}/progress") for c in world.calls)


# ---------------------------------------------------------------- posture review
def test_posture_review_is_a_redacted_draft_once_a_month(world):
    db = SessionLocal()
    brain.cycle(db)
    month = utcnow().strftime("%Y-%m")
    rb = next(i for i in world.communications["plat-rb"] if i["kind"] == "posture_review")
    hp = next(i for i in world.communications["plat-hp"] if i["kind"] == "posture_review")
    assert rb["status"] == "draft" and rb["source_ref"] == f"review:plat-rb:{month}"
    assert rb["subject"].startswith("Your security posture review for ")
    body = rb["body_md"]
    assert "## What SABINE did on your account" in body and "Page the on-call responder" in body
    assert "acknowledge a critical detection within 10 minutes" in body and "MDR-2026-0007" in body
    # redacted for Riverbend: no other client, no Vendetta person, no console link, no token
    for leak in ("Harbor Point", "Dan", "Idle", "Jordan", "vendettacd.io", "https://"):
        assert leak not in body, leak
    for leak in ("Riverbend", "WS01", "SRV02", "https://", "Dan"):
        assert leak not in hp["body_md"], leak
    assert "VCD-IR-2026-790" in hp["body_md"]
    # posted as a draft: the result says a person still approves, and nothing was sent anywhere else
    p = _props(db, "posture_review")[f"posture_review:plat-rb:{month}"]
    assert p.result["draft"] is True and p.result["created"] is True and "waiting for approval" in p.result["detail"]
    assert not any(c[1] == "POST" and c[0] == "platform" and not (c[2].endswith("/communications") or c[2].endswith("/journey"))
                   for c in world.calls)
    # once a month: the next cycle and the next day do not draft it again
    brain.cycle(db)
    p.executed_at = utcnow() - dt.timedelta(days=2)
    db.commit()
    brain.cycle(db)
    assert len([i for i in world.communications["plat-rb"] if i["kind"] == "posture_review"]) == 1
    assert db.query(Proposal).filter_by(action="posture_review").count() == 2


def test_posture_review_uses_the_formal_client_voice(world, monkeypatch):
    seen = []

    def fake(prompt, max_tokens=900, audience="internal", system_text=None):
        seen.append((audience, prompt))
        return "Harbor Point and Dan send regards. Things are steady."
    monkeypatch.setattr(settings, "anthropic_api_key", "k")
    monkeypatch.setattr(narrative, "_complete", fake)
    db = SessionLocal()
    brain.cycle(db)
    reviews = [(a, p) for a, p in seen if "monthly security posture review" in p]
    assert reviews and all(a == "client" for a, _ in reviews)
    assert "dry wit" not in narrative.system("client") and "formal" in narrative.system("client")
    rb = next(i for i in world.communications["plat-rb"] if i["kind"] == "posture_review")
    assert "another client and your Vendetta team send regards" in rb["body_md"]
    prompt = next(p for _, p in reviews if "'client': 'Riverbend Credit Union'" in p)
    assert "Harbor Point" not in prompt and "'lead'" not in prompt


# ---------------------------------------------------------------- client outreach
def test_client_outreach_drafts_for_campaign_acceptance_and_commitment(world):
    # the same ransomware pattern at Harbor Point; a deliverable 20 days unaccepted; i1 open 100 of 120 minutes
    world.findings["managed-services"].append(_finding("managed-services", "al9", "critical", "Ransomware behavior on WS07",
                                                       pid="plat-hp", client="Harbor Point", type="threat", matched="WS07"))
    world.engagements[0]["deliverables"][0]["delivered_at"] = (NOW - dt.timedelta(days=20)).isoformat()
    world.findings["mdr"][0]["opened_at"] = (NOW - dt.timedelta(minutes=100)).isoformat()
    db = SessionLocal()
    brain.cycle(db)
    out = _props(db, "client_outreach")
    camp = [k for k in out if k.startswith("client_outreach:campaign:")]
    assert len(camp) == 2 and all(out[k].status == "executed" and out[k].result["draft"] for k in camp)
    assert out["client_outreach:acceptance:d1"].status == "executed"
    assert out["client_outreach:commitment:i1"].facts["contain_minutes"] == 120
    rb = {i["source_ref"].split(":")[0]: i for i in world.communications["plat-rb"] if i["kind"] == "outreach"}
    hp = [i for i in world.communications["plat-hp"] if i["kind"] == "outreach"]
    assert set(rb) == {"campaign", "acceptance", "commitment"} and len(hp) == 1
    assert "several organizations" in rb["campaign"]["body_md"] and "Harbor Point" not in rb["campaign"]["body_md"]
    assert "Riverbend" not in hp[0]["body_md"] and "WS01" not in hp[0]["body_md"] and "WS07" in hp[0]["body_md"]
    assert rb["acceptance"]["subject"] == "Your review of Information Security Policy v1" and "Jordan" not in rb["acceptance"]["body_md"]
    assert "MDR-2026-0007" in rb["commitment"]["subject"] and "120 minutes" in rb["commitment"]["body_md"]
    assert all(i["status"] == "draft" for i in world.communications["plat-rb"])
    # dedupe: the same reasons do not draft twice
    n = sum(len(v) for v in world.communications.values())
    brain.cycle(db)
    assert sum(len(v) for v in world.communications.values()) == n


# ---------------------------------------------------------------- suppression from decision memory
def test_suggest_suppression_after_n_noise_calls_then_approve(world):
    db = SessionLocal()
    brain.cycle(db)
    assert not _props(db, "suggest_suppression")  # two closed as false positive: below the threshold of 3
    world.mdr_closed.append(_investigation("x3", "medium", "Scheduled task created by admin tool on SRV03", "MDR-2026-0003",
                                           (NOW - dt.timedelta(days=1)).isoformat(), matched="SRV03", native_status="closed",
                                           verdict="false_positive", rule="schtask"))
    brain.cycle(db)
    p = next(iter(_props(db, "suggest_suppression").values()))
    assert p.status == "pending" and p.risk == "medium" and p.autonomy == "propose"
    assert p.target["title_contains"] == "Scheduled task created by admin tool on" and p.target["days"] == 30
    assert p.facts["false_positive"] == 3 and p.facts["rejected"] == 0 and p.facts["threshold"] == 3
    assert not world.suppressions  # nothing happens until a person approves
    res = brain.decide(db, p, "dan@vendettacd.io", True, "agreed, it is the backup tool")
    assert res["ok"] and res["suppression"]
    s = world.suppressions[0]
    assert s["platform_client_id"] == "plat-rb" and s["created_by"] == "sabine (approved by dan@vendettacd.io)"
    assert ("mdr", "POST", "/api/suppressions", "Bearer mdrtok", "sabine") in world.calls
    # the suppression in force covers the pattern: nothing new is proposed
    db.query(Proposal).filter_by(id=p.id).update({"executed_at": utcnow() - dt.timedelta(days=3)})
    db.commit()
    brain.cycle(db)
    assert db.query(Proposal).filter_by(action="suggest_suppression").count() == 1


def test_rejections_feed_memory_and_a_rejected_suggestion_cools_down(world):
    db = SessionLocal()
    # a live MDR detection of the same pattern; people reject its escalation
    world.findings["mdr"].append(_investigation("i5", "high", "Scheduled task created by admin tool on SRV09", "MDR-2026-0012",
                                                OLD, matched="SRV09", rule="schtask"))
    brain.cycle(db)
    e = _props(db, "escalate_finding")["escalate_finding:mdr:i5"]
    assert e.confidence == 0.75 and "memory" not in e.facts and e.facts["signature"] == "scheduled task created by admin tool on srv#"
    brain.decide(db, e, "dan@vendettacd.io", False, "noise")
    brain.cycle(db)
    # decision memory: the re-raised escalation carries the rejection and a lower confidence
    again = db.query(Proposal).filter_by(key="escalate_finding:mdr:i5", status="pending").one()
    assert again.facts["memory"] == {"signature": "scheduled task created by admin tool on srv#", "approved": 0, "rejected": 1,
                                     "base": 0.75, "adjustment": -0.1}
    assert again.confidence == 0.65 and "Decision memory" in again.rationale
    # two false positives plus one rejection make three: SABINE proposes the suppression
    sug = next(iter(_props(db, "suggest_suppression").values()))
    assert sug.facts["false_positive"] == 2 and sug.facts["rejected"] == 1 and sug.status == "pending"
    brain.decide(db, sug, "dan@vendettacd.io", False, "keep watching it")
    brain.cycle(db)
    assert db.query(Proposal).filter_by(action="suggest_suppression").count() == 1  # cooling down for a week


# ---------------------------------------------------------------- the daily summary and the metrics
def test_daily_summary_mentions_drafts_waiting_and_pages_sent(world):
    db = SessionLocal()
    brain.cycle(db)
    first = db.query(Brief).filter_by(kind="daily-summary").one()
    assert "## Pages sent" in first.body_md and "2 page(s) to the on-call responder today" in first.body_md
    for p in db.query(Proposal).filter_by(action="daily_summary").all():
        p.status = "expired"
    db.commit()
    brain.cycle(db)
    second = db.query(Brief).filter_by(kind="daily-summary").order_by(Brief.created_at.desc()).first()
    assert "## Communications waiting for approval" in second.body_md
    assert "2 client communication(s) are drafts on the platform" in second.body_md and "posture review" in second.body_md


def test_mean_time_to_trusted_action_leaves_drafts_out(world):
    db = SessionLocal()
    brain.cycle(db)
    m = metrics.get(db, ttl=0)["windows"][7]
    drafts = db.query(Proposal).filter(Proposal.action.in_(("posture_review", "client_outreach")), Proposal.status == "executed").count()
    auto_ok = db.query(Proposal).filter(Proposal.status == "executed", Proposal.autonomy == "auto").count()
    assert drafts == 2 and m["drafted"] == drafts and m["auto"]["ok"] == auto_ok - drafts
    assert m["autonomous_share"] == round((auto_ok - drafts) / m["proposals_raised"], 3)
    assert "2 client drafts handed to a person on the platform" in metrics.line(metrics.get(db, ttl=0))
    # pure function: a draft action neither times nor counts as closed
    t0 = NOW - dt.timedelta(hours=1)
    rows = [{"at": t0, "kind": "proposal", "ref": "a", "summary": "posture_review: x", "detail": {}},
            {"at": t0 + dt.timedelta(seconds=5), "kind": "action", "ref": "a", "summary": "posture_review done: x",
             "detail": {"autonomy": "auto", "result": {"ok": True, "draft": True}}},
            {"at": t0, "kind": "proposal", "ref": "b", "summary": "page_oncall: y", "detail": {}},
            {"at": t0 + dt.timedelta(seconds=9), "kind": "action", "ref": "b", "summary": "page_oncall done: y",
             "detail": {"autonomy": "auto", "result": {"ok": True, "sent": {"teams": "sent"}}}}]
    w = metrics.compute(rows, now=NOW)["windows"][7]
    assert w["drafted"] == 1 and w["auto"]["ok"] == 1 and w["auto"]["median_s"] == 9.0 and w["autonomous_share"] == 0.5


def test_internal_skills_stay_out_of_the_client_brief(world):
    db = SessionLocal()
    brain.cycle(db)
    from app import executor
    acts = executor.client_actions(db, {"id": "plat-rb", "name": "Riverbend Credit Union"}, days=31)
    whats = {a["what"] for a in acts}
    assert "Page the on-call responder for an unacknowledged critical" in whats
    assert not whats & {"Draft the monthly posture review", "Propose a Security Journey item from evidence", "Write a client brief"}
