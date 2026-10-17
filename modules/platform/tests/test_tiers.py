"""Client tier, account lead and response commitments: defaults by tier, per-client
overrides, the edit form's validation, and the fields modules and SABINE read from
GET /api/platform/clients."""
from app.db import Client, SessionLocal
from helpers import bearer, make_client


def test_new_client_defaults_to_core_commitments(admin):
    c = make_client(admin)
    assert c.tier == "core" and c.account_lead == "" and c.portal_enabled is False
    assert c.commitments() == {"critical_ack_minutes": 15, "critical_contain_minutes": 240}


def test_tier_defaults_and_overrides(admin):
    c = make_client(admin, tier="advanced")
    assert SessionLocal().get(Client, c.id).commitments() == {"critical_ack_minutes": 10,
                                                              "critical_contain_minutes": 120}
    admin.post(f"/clients/{c.id}/edit", data={"active": "true", "tier": "premier", "critical_ack_minutes": "3",
                                              "critical_contain_minutes": ""})
    c = SessionLocal().get(Client, c.id)
    assert c.tier == "premier" and c.critical_ack_minutes == 3 and c.critical_contain_minutes is None
    assert c.commitments() == {"critical_ack_minutes": 3, "critical_contain_minutes": 60}
    # clearing the override returns to the tier default
    admin.post(f"/clients/{c.id}/edit", data={"active": "true", "tier": "premier", "critical_ack_minutes": ""})
    assert SessionLocal().get(Client, c.id).commitments()["critical_ack_minutes"] == 5


def test_edit_validates_tier_minutes_and_lead(admin):
    c = make_client(admin)
    for bad in ({"tier": "platinum"}, {"critical_ack_minutes": "soon"}, {"critical_contain_minutes": "0"},
                {"account_lead": "dan"}):
        r = admin.post(f"/clients/{c.id}/edit", data={"active": "true", **bad}, follow_redirects=False)
        assert "err=" in r.headers["location"], bad
    c = SessionLocal().get(Client, c.id)
    assert c.tier == "core" and c.critical_ack_minutes is None and c.account_lead == ""


def test_lead_portal_switch_and_partial_edit(admin):
    c = make_client(admin, tier="advanced", account_lead=" Dan@VendettaCD.io ", portal_enabled="true")
    c = SessionLocal().get(Client, c.id)
    assert c.account_lead == "dan@vendettacd.io" and c.portal_enabled is True
    # the form sends a hidden false then the checkbox; unticked leaves only the hidden false
    admin.post(f"/clients/{c.id}/edit", data={"active": "true", "portal_enabled": "false"})
    assert SessionLocal().get(Client, c.id).portal_enabled is False
    # a caller that omits tier, lead and the switch leaves them as they were
    admin.post(f"/clients/{c.id}/edit", data={"active": "true", "industry": "credit union"})
    c = SessionLocal().get(Client, c.id)
    assert c.tier == "advanced" and c.account_lead == "dan@vendettacd.io" and c.industry == "credit union"


def test_client_page_shows_tier_lead_and_commitments(admin):
    c = make_client(admin, tier="premier", account_lead="dan@vendettacd.io", critical_contain_minutes="45")
    page = admin.get(f"/clients/{c.id}").text
    assert "Premier" in page and "dan@vendettacd.io" in page
    assert "5 min" in page and "45 min" in page and "(override)" in page
    assert "Client 360" in page and "Security Journey" in page
    listing = admin.get("/clients").text
    assert "Premier" in listing


def test_provisioning_api_carries_tier_lead_commitments_services(admin):
    c = make_client(admin, tier="advanced", account_lead="dan@vendettacd.io", critical_ack_minutes="7")
    admin.post(f"/clients/{c.id}/modules/managed-services", data={"enabled": "true"})
    admin.post(f"/clients/{c.id}/modules/mdr", data={"enabled": "true"})
    out = admin.get("/api/platform/clients", headers=bearer()).json()["clients"][0]
    assert out["tier"] == "advanced" and out["account_lead"] == "dan@vendettacd.io"
    assert out["commitments"] == {"critical_ack_minutes": 7, "critical_contain_minutes": 120}
    assert out["services"] == ["managed-services", "mdr"] == out["modules"]
    scoped = admin.get("/api/platform/clients", params={"module": "mdr"}, headers=bearer()).json()["clients"]
    assert [x["id"] for x in scoped] == [c.id] and scoped[0]["commitments"]["critical_ack_minutes"] == 7
