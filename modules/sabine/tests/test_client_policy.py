"""Per-client tuning: autonomy overrides per (client, skill) and thresholds per
client, set on the Autonomy page, written to the ledger, and used by propose().
A high-risk skill is never automatic for any client."""
import datetime as dt

import pytest

from app import brain, ledger, memory, perception, policy
from app.db import ClientPolicy, ClientThreshold, Ledger, Proposal, SessionLocal

from conftest import NOW


def test_client_override_beats_the_global_level(world):
    db = SessionLocal()
    perception.observe(db)
    policy.set_client_autonomy(db, "plat-rb", "escalate_finding", "auto", "admin", "Riverbend Credit Union")
    assert policy.autonomy(db, "escalate_finding") == "propose"
    assert policy.autonomy(db, "escalate_finding", "plat-rb") == "auto"
    assert policy.autonomy(db, "escalate_finding", {"id": "plat-hp"}) == "propose"
    brain.cycle(db)
    rb = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    hp = db.query(Proposal).filter_by(key="escalate_finding:vulnerability-management:v1").one()
    assert rb.autonomy == "auto" and rb.status == "executed" and ("dark-web-monitoring", "dw1") in world.escalations
    assert hp.autonomy == "propose" and hp.status == "pending"
    # off for one client switches the rule off there only
    policy.set_client_autonomy(db, "plat-hp", "posture_review", "off", "admin", "Harbor Point")
    db.query(Proposal).filter_by(action="posture_review").delete()
    world.communications = {"plat-rb": [], "plat-hp": []}
    db.commit()
    brain.cycle(db)
    assert {p.target["platform_client_id"] for p in db.query(Proposal).filter_by(action="posture_review").all()} == {"plat-rb"}


def test_high_risk_is_never_auto_for_any_client(world):
    db = SessionLocal()
    with pytest.raises(ValueError):
        policy.set_client_autonomy(db, "plat-rb", "host_action", "auto", "admin")
    # even a row forced in behind the API's back is capped at propose
    db.add(ClientPolicy(platform_client_id="plat-rb", action="host_action", autonomy="auto"))
    db.commit()
    assert policy.autonomy(db, "host_action", "plat-rb") == "propose"
    brain.cycle(db)
    h = db.query(Proposal).filter_by(key="host_action:al1").one()
    assert h.autonomy == "propose" and h.status == "pending" and h.facts["platform_client_id"] == "plat-rb"
    # propose and off are allowed for a high-risk skill
    policy.set_client_autonomy(db, "plat-rb", "host_action", "off", "admin")
    assert policy.autonomy(db, "host_action", "plat-rb") == "off"


def test_client_thresholds(world):
    db = SessionLocal()
    perception.observe(db)
    with pytest.raises(ValueError):
        policy.set_thresholds(db, "plat-rb", {"critical_ack_minutes": "soon"}, "admin")
    policy.set_thresholds(db, "plat-rb", {"critical_ack_minutes": "60", "escalate_after_minutes": "600"}, "admin", "Riverbend Credit Union")
    policy.set_thresholds(db, "plat-hp", {"stale_case_days": "30"}, "admin", "Harbor Point")
    assert policy.critical_ack(db, perception.client(db, "plat-rb")) == (60, "client override")
    assert policy.critical_ack(db, perception.client(db, "plat-hp")) == (15, "core commitment")
    brain.cycle(db)
    props = {p.key: p for p in db.query(Proposal).all()}
    # i1 (40m) is inside the 60-minute override; al1 (120m) is past it
    assert "page_oncall:mdr:i1" not in props and props["page_oncall:managed-services:al1"].facts["commitment_source"] == "client override"
    # Riverbend escalates after 600 minutes now; Harbor Point's 8-day-quiet case is inside its 30 days
    assert "escalate_finding:dark-web-monitoring:dw1" not in props and "stale_case:c1" not in props
    assert "escalate_finding:vulnerability-management:v1" in props
    # all blank resets the client to the defaults
    assert policy.set_thresholds(db, "plat-hp", {}, "admin") is None and db.get(ClientThreshold, "plat-hp") is None


def test_autonomy_page_manages_overrides_and_writes_the_ledger(admin, world):
    db = SessionLocal()
    perception.observe(db)
    r = admin.post("/policy/client", data={"platform_client_id": "plat-rb", "action": "escalate_finding", "autonomy": "auto"},
                   follow_redirects=False)
    assert r.status_code == 302 and "msg=" in r.headers["location"]
    r = admin.post("/policy/client", data={"platform_client_id": "plat-rb", "action": "host_action", "autonomy": "auto"},
                   follow_redirects=False)
    assert "err=" in r.headers["location"]
    r = admin.post("/policy/client", data={"platform_client_id": "nobody", "action": "escalate_finding", "autonomy": "auto"},
                   follow_redirects=False)
    assert "err=" in r.headers["location"]
    page = admin.get("/policy")
    assert page.status_code == 200 and "Per-client autonomy" in page.text and "Riverbend Credit Union" in page.text
    assert "Per-client thresholds" in page.text
    o = SessionLocal().query(ClientPolicy).one()
    assert (o.platform_client_id, o.action, o.autonomy, o.client) == ("plat-rb", "escalate_finding", "auto", "Riverbend Credit Union")
    admin.post("/policy/thresholds", data={"platform_client_id": "plat-rb", "critical_ack_minutes": "20"})
    assert SessionLocal().get(ClientThreshold, "plat-rb").critical_ack_minutes == 20
    assert admin.post(f"/policy/client/{o.id}/remove", follow_redirects=False).status_code == 302
    admin.post("/policy/thresholds/plat-rb/remove")
    db = SessionLocal()
    assert db.query(ClientPolicy).count() == 0 and db.get(ClientThreshold, "plat-rb") is None
    rows = [x.summary for x in db.query(Ledger).filter_by(kind="decision").order_by(Ledger.chain_seq).all()]
    assert rows == ["policy: escalate_finding for Riverbend Credit Union -> auto", "thresholds: Riverbend Credit Union -> critical_ack_minutes=20",
                    "policy: escalate_finding for Riverbend Credit Union -> global", "thresholds: Riverbend Credit Union -> defaults"]
    assert ledger.verify(db)["ok"]


def test_overrides_need_an_admin(client, world):
    from app import auth
    from app.db import User
    db = SessionLocal()
    perception.observe(db)
    db.add(User(email="kim@vendettacd.io", role="analyst", source="platform"))
    db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("kim@vendettacd.io"))
    r = client.post("/policy/client", data={"platform_client_id": "plat-rb", "action": "escalate_finding", "autonomy": "auto"})
    assert r.status_code == 403
    assert client.post("/policy/thresholds", data={"platform_client_id": "plat-rb", "critical_ack_minutes": "5"}).status_code == 403
    page = client.get("/policy")
    assert page.status_code == 200 and "Add override" not in page.text
    assert SessionLocal().query(ClientPolicy).count() == 0


# ---------------------------------------------------------------- decision memory
def test_signature_normalises_instances_of_one_pattern():
    s = memory.signature
    assert s("Ransomware behavior on WS01") == s("Ransomware behavior on WS07") == "ransomware behavior on ws#"
    assert s("Login from 10.2.3.4 see https://x.example/a/1") == "login from #.#.#.# see"
    assert s("Hash 0123456789abcdef0123 seen") == "hash # seen"
    assert memory.sig_hash("a") == memory.sig_hash("a") and len(memory.sig_hash("a")) == 12
    assert memory.common_phrase(["Scheduled task on SRV01", "Scheduled task on SRV02"]) == "Scheduled task on"
    assert memory.common_phrase(["abc", "xyz"]) == "xyz"


def test_memory_adjustment_is_bounded_and_recorded(world):
    db = SessionLocal()
    sig = "rb combolist leak"
    for i in range(8):
        db.add(Proposal(key=f"k{i}", action="escalate_finding", title="t", facts={"platform_client_id": "plat-rb", "title": "RB combolist leak"},
                        target={}, status="rejected", decided_by="dan@vendettacd.io", decided_at=NOW))
    db.commit()
    conf, rec = memory.adjust(db, "escalate_finding", "plat-rb", sig, 0.9)
    assert rec["rejected"] == 8 and rec["adjustment"] == -0.5 and conf == 0.4  # bounded at -0.5
    assert memory.adjust(db, "escalate_finding", "plat-hp", sig, 0.9) == (0.9, None)  # another client: no history
    assert memory.adjust(db, "page_oncall", "plat-rb", sig, 0.9) == (0.9, None)  # another skill: no history
    for i in range(10):
        db.add(Proposal(key=f"a{i}", action="client_brief", title="Brief", facts={"platform_client_id": "plat-rb", "signature": "brief"},
                        target={}, status="executed", decided_by="dan@vendettacd.io", decided_at=NOW))
    db.commit()
    conf, rec = memory.adjust(db, "client_brief", "plat-rb", "brief", 0.9)
    assert rec["approved"] == 10 and conf == 0.99  # bounded at 0.99
    # undecided (automatic) proposals are not decisions
    db.add(Proposal(key="z", action="page_oncall", title="x", facts={"platform_client_id": "plat-rb", "signature": "x"}, target={},
                    status="executed"))
    db.commit()
    assert memory.history(db, "page_oncall", "plat-rb", "x") == {"approved": 0, "rejected": 0}
    old = Proposal(key="o", action="page_oncall", title="x", facts={"platform_client_id": "plat-rb", "signature": "x"}, target={},
                   status="rejected", decided_at=NOW, created_at=NOW - dt.timedelta(days=400))
    db.add(old)
    db.commit()
    assert memory.history(db, "page_oncall", "plat-rb", "x")["rejected"] == 0  # outside the lookback
