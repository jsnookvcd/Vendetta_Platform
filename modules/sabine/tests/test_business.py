"""Running the business from Harvest and HubSpot: connectors with mockable
transports, the four business skills, readiness when a source is not configured,
and the Business and Concierge pages."""
from app import auth, brain, business, perception, readiness
from app.config import settings
from app.db import Proposal, SessionLocal, WorkItem

from conftest import NOW


def _props(db, action):
    return {p.key: p for p in db.query(Proposal).filter_by(action=action).all()}


def test_unconfigured_sources_are_skipped_and_reported(world):
    db = SessionLocal()
    summary = brain.cycle(db)
    assert not any(k.startswith(("harvest:", "hubspot:")) for k in summary["seen"])
    assert business.status() == {"harvest": "not configured", "hubspot": "not configured"}
    assert readiness.integrations()["business"] == {"harvest": "not configured", "hubspot": "not configured"}
    assert db.query(Proposal).filter(Proposal.action.in_(("engagement_budget_burn", "capacity_overload", "renewal_upcoming",
                                                          "won_not_onboarded"))).count() == 0


def test_connectors_send_the_right_headers_and_shape_the_data(biz):
    h = business.harvest()
    projects = {p["id"]: p for p in h.projects()}
    assert projects["101"]["pct"] == 85.0 and projects["103"]["pct"] is None
    people = {u["email"]: u for u in h.capacity(NOW.date())}
    assert people["dan@vendettacd.io"]["capacity_hours"] == 40.0 and people["dan@vendettacd.io"]["pct"] == 116.2
    hv = [c for c in biz.calls if c[0] == "api.harvestapp.com"]
    assert all(c[3]["harvest-account-id"] == "12345" and c[3]["authorization"] == "Bearer hv-token" for c in hv)
    team = next(c for c in hv if c[2] == "/v2/reports/time/team")
    assert team and {c[2] for c in hv} == {"/v2/reports/project_budget", "/v2/users", "/v2/reports/time/team"}
    deals = business.hubspot().deals(60, 30, NOW.date())
    assert deals["renewals"][0]["company"] == "Riverbend Credit Union" and deals["renewals"][0]["amount"] == 48000.0
    assert {d["company"] for d in deals["won"]} == {"Lakeside Bank, Inc.", "Harbor Point", "Fresh Co"}
    search = [c for c in biz.calls if c[2] == "/crm/v3/objects/deals/search"]
    assert b'"dealtype"' in search[0][4] and b'"renewal"' in search[0][4] and search[0][3]["authorization"] == "Bearer hs-token"


def test_business_rules_raise_work_items(biz):
    db = SessionLocal()
    summary = brain.cycle(db)
    assert summary["seen"]["harvest:projects"] and summary["seen"]["harvest:capacity"] and summary["seen"]["hubspot:deals"]
    burn = _props(db, "engagement_budget_burn")
    assert set(burn) == {"engagement_budget_burn:101:80"}
    b = burn["engagement_budget_burn:101:80"]
    assert b.status == "executed" and b.facts["pct"] == 85.0 and "17,000 of 20,000" in b.rationale
    cap = _props(db, "capacity_overload")
    assert len(cap) == 1 and next(iter(cap.values())).facts["email"] == "dan@vendettacd.io"
    ren = _props(db, "renewal_upcoming")["renewal_upcoming:501"]
    assert ren.facts["days"] == 21 and ren.facts["matched_client"] == "Riverbend Credit Union"
    assert ren.facts["posture"]["active_findings"]["critical"] >= 3 and "active findings" in ren.rationale
    won = _props(db, "won_not_onboarded")
    assert set(won) == {"won_not_onboarded:601"}  # Harbor Point is a client; the fresh win is inside the grace days
    assert "Lakeside Bank, Inc." in won["won_not_onboarded:601"].title
    kinds = {w.kind for w in db.query(WorkItem).filter_by(source="sabine").all()}
    assert {"budget", "capacity", "renewal", "onboarding"} <= kinds
    # internal work never reaches a client brief
    from app import executor
    whats = {a["what"] for a in executor.client_actions(db, {"id": "plat-rb", "name": "Riverbend Credit Union"})}
    assert "Flag a renewal coming up" not in whats and "Flag an engagement burning through its budget" not in whats
    # dedupe: the next cycle raises nothing new; crossing 100% raises the next band
    n = db.query(Proposal).count()
    brain.cycle(db)
    assert db.query(Proposal).count() == n
    biz.projects[0]["budget_spent"] = 21000.0
    brain.cycle(db)
    assert "engagement_budget_burn:101:100" in _props(db, "engagement_budget_burn")


def test_a_rejected_token_degrades_the_source(biz, monkeypatch):
    monkeypatch.setattr(settings, "harvest_token", "wrong")
    db = SessionLocal()
    summary = brain.cycle(db)
    assert summary["seen"]["harvest:projects"] is False
    assert perception.snapshots(db)["harvest:projects"].detail == "Harvest rejected the token"
    assert not _props(db, "engagement_budget_burn") and _props(db, "renewal_upcoming")


def test_business_page_renders_configured_and_not(admin, world, monkeypatch):
    brain.cycle(SessionLocal())
    r = admin.get("/business")
    assert r.status_code == 200 and r.text.count("not configured") >= 2 and "HARVEST_ACCOUNT_ID" in r.text and "HUBSPOT_TOKEN" in r.text


def test_business_page_with_data(admin, biz):
    brain.cycle(SessionLocal())
    r = admin.get("/business")
    assert r.status_code == 200
    for text in ("Engagement budget burn", "Riverbend vCISO", "85%", "Capacity this week", "Dan Baker", "116%",
                 "Renewals", "Riverbend renewal 2027", "48,000", "New wins", "Lakeside Bank, Inc.", "not yet", "onboarded"):
        assert text in r.text, text
    api = admin.get("/api/business", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert api["status"] == {"harvest": "configured", "hubspot": "configured"} and api["thresholds"]["budget_burn_pct"] == 80
    assert {d["company"]: d["onboarded"] for d in api["won"]}["Harbor Point"] is True


def test_concierge_page_lists_what_sabine_raised_per_client(admin, world):
    db = SessionLocal()
    brain.cycle(db)
    brain.cycle(db)  # the second pass reads back the items the first one created
    r = admin.get("/concierge")
    assert r.status_code == 200
    for text in ("Riverbend Credit Union", "Harbor Point", "Enforce MFA everywhere and rotate exposed credentials",
                 "Bring endpoints under 24x7 managed detection and response", "posture review", "waiting for the account lead",
                 "proposed", "https://platform.example/clients/plat-rb"):
        assert text in r.text, text
    world.communications["plat-rb"][0].update(status="approved", decided_by="dan@vendettacd.io")
    brain.cycle(db)
    r = admin.get("/concierge")
    assert "approved" in r.text and "dan@vendettacd.io" in r.text
    api = admin.get("/api/concierge", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    rb = next(x for x in api if x["platform_client_id"] == "plat-rb")
    assert rb["journey"][0]["source_ref"] == "gap:plat-rb:credentials" and "body_md" not in rb["communications"][0]
    # navigation carries both tabs
    assert 'href="/concierge"' in r.text and 'href="/business"' in r.text
