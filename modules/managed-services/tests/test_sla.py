"""SLA clocks: the pure engine (targets, live status, adherence, roll-ups) and the
wiring that stamps acknowledge/contain times and surfaces a client-safe service
level on the portal."""
import datetime as dt
from types import SimpleNamespace

from app import auth, sla
from app.db import Alert, Client, SessionLocal

from test_app import FakeS1, _client_with_s1, _portal_session, _synced_alert

NOW = dt.datetime(2026, 10, 13, 18, 0, tzinfo=dt.timezone.utc)


def _alert(sev="critical", status="open", received_min_ago=0, ack_min_ago=None, contain_min_ago=None):
    def at(m):
        return None if m is None else NOW - dt.timedelta(minutes=m)
    return SimpleNamespace(severity=sev, status=status, received_at=at(received_min_ago),
                           acknowledged_at=at(ack_min_ago), contained_at=at(contain_min_ago),
                           synced_at=at(received_min_ago), occurred_at=at(received_min_ago),
                           updated_at=NOW)


# ----- pure engine -----

def test_targets_and_governed():
    assert sla.targets("standard", "critical") == (15, 60)
    assert sla.targets("priority", "critical") == (10, 30)
    assert sla.targets("standard", "info") == (None, None)
    assert sla.governed("standard", "critical") is True
    assert sla.governed("standard", "info") is False
    assert sla.governed("monitor", "critical") is False


def test_live_status_ack_phase_states():
    # fresh critical (ack target 15, at-risk window 10): 14 min left = on track
    assert sla.live_status(_alert(received_min_ago=1), "standard", NOW)["state"] == "on_track"
    # critical 8 min in: 7 min left, inside the 10-min window = at risk
    assert sla.live_status(_alert(received_min_ago=8), "standard", NOW)["state"] == "at_risk"
    # a high alert seen 2 min ago is on track (ack target 30, window 10)
    assert sla.live_status(_alert("high", received_min_ago=2), "standard", NOW)["state"] == "on_track"
    # critical past its 15-min ack target with no ack = breached
    st = sla.live_status(_alert(received_min_ago=50), "standard", NOW)
    assert st["phase"] == "ack" and st["state"] == "breached" and st["remaining_seconds"] < 0


def test_live_status_moves_to_contain_then_done():
    # acknowledged promptly, contain target 60 still has time left
    a = _alert(received_min_ago=20, ack_min_ago=18)
    st = sla.live_status(a, "standard", NOW)
    assert st["phase"] == "contain" and st["state"] in ("on_track", "at_risk")
    # contained -> done
    a2 = _alert(received_min_ago=20, ack_min_ago=18, contain_min_ago=5)
    assert sla.live_status(a2, "standard", NOW)["phase"] == "done"
    # monitor profile has no clock
    assert sla.live_status(_alert(received_min_ago=50), "monitor", NOW)["state"] == "none"


def test_adherence_met_missed_pending():
    met = _alert(received_min_ago=30, ack_min_ago=25, contain_min_ago=0, status="resolved")
    ad = sla.adherence(met, "standard")
    assert ad["ack"]["result"] == "met" and ad["contain"]["result"] == "met" and ad["overall"] == "met"
    # acked late -> missed
    late = _alert(received_min_ago=40, ack_min_ago=0)
    assert sla.adherence(late, "standard", NOW)["ack"]["result"] == "missed"
    # still fresh and unacked -> pending, overall na
    fresh = _alert("high", received_min_ago=2)
    adf = sla.adherence(fresh, "standard", NOW)
    assert adf["ack"]["result"] == "pending" and adf["overall"] == "na"


def test_summarize_and_response_stats():
    pairs = [
        (_alert(received_min_ago=30, ack_min_ago=25, contain_min_ago=0, status="resolved"), "standard"),  # met
        (_alert(received_min_ago=90, ack_min_ago=0, status="resolved"), "standard"),  # ack missed
        (_alert(received_min_ago=50), "standard"),  # open, breached
    ]
    s = sla.summarize(pairs, NOW)
    assert s["met"] == 1 and s["missed"] == 2 and s["graded"] == 3
    assert s["adherence_rate"] == round(100 / 3, 1)
    assert s["breached"] == 1
    rs = sla.response_stats(pairs)
    assert rs["ack_count"] >= 2 and rs["ack_median_min"] is not None


def test_mark_helpers_are_idempotent_and_backfill():
    a = _alert(received_min_ago=10)
    sla.mark_acknowledged(a, NOW)
    first = a.acknowledged_at
    sla.mark_acknowledged(a, NOW + dt.timedelta(minutes=5))
    assert a.acknowledged_at == first  # not overwritten
    b = _alert(received_min_ago=10)
    sla.mark_contained(b, NOW)
    assert b.contained_at == NOW and b.acknowledged_at == NOW  # contain backfills ack


# ----- wiring -----

def test_triage_acknowledge_and_resolve_stamp_clocks(admin):
    fake, c, a = _synced_alert(admin)
    admin.post(f"/alerts/{a.id}/triage", data={"op": "acknowledge"})
    row = SessionLocal().get(Alert, a.id)
    assert row.acknowledged_at is not None and row.contained_at is None
    admin.post(f"/alerts/{a.id}/triage", data={"op": "resolve"})
    row = SessionLocal().get(Alert, a.id)
    assert row.contained_at is not None


def test_destructive_action_stamps_contained(admin):
    fake, c, a = _synced_alert(admin)
    admin.post(f"/alerts/{a.id}/action", data={"action_id": "s1_quarantine", "confirm": "true"})
    row = SessionLocal().get(Alert, a.id)
    assert ("mitigate", "quarantine", ["t9"]) in fake.calls
    assert row.acknowledged_at is not None and row.contained_at is not None


def test_portal_shows_client_safe_service_level_scoped_to_one_client(admin):
    fake, c, a = _synced_alert(admin)
    # one met, one missed, on THIS client
    db = SessionLocal()
    c = db.get(Client, c.id)
    now = dt.datetime.now(dt.timezone.utc)
    db.add(Alert(client_id=c.id, tool="sentinelone", external_id="m-met", severity="high",
                 title="Phishing page blocked", status="resolved",
                 received_at=now - dt.timedelta(minutes=20), acknowledged_at=now - dt.timedelta(minutes=18),
                 contained_at=now - dt.timedelta(minutes=10)))
    db.add(Alert(client_id=c.id, tool="sentinelone", external_id="m-missed", severity="critical",
                 title="Beacon detected", status="resolved",
                 received_at=now - dt.timedelta(hours=5), acknowledged_at=now - dt.timedelta(hours=4)))
    # a different client's breach must not touch this client's number
    other = Client(name="Unrelated Co", sla_profile="standard")
    db.add(other); db.flush()
    db.add(Alert(client_id=other.id, tool="sentinelone", external_id="o-1", severity="critical",
                 title="Other", status="open", received_at=now - dt.timedelta(hours=9)))
    db.commit()

    _portal_session(admin, "cfo@riverbendcu.org", c)
    page = admin.get("/portal").text
    assert "Service levels" in page
    assert "SLA met" in page
    assert "Unrelated Co" not in page and "Other" not in page


def test_admin_sets_client_sla_profile_and_non_admin_cannot(admin, client):
    fake, c, a = _synced_alert(admin)
    # admin session (the `admin` fixture is logged in as the built-in admin)
    r = admin.post(f"/clients/{c.id}/sla", data={"sla_profile": "priority"}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert SessionLocal().get(Client, c.id).sla_profile == "priority"
    # an unknown profile is rejected
    assert admin.post(f"/clients/{c.id}/sla", data={"sla_profile": "bogus"}).status_code == 400
    # a non-admin internal user cannot change it
    db = SessionLocal()
    from app.db import User
    if not db.query(User).filter_by(email="analyst@vendettacd.io").count():
        db.add(User(email="analyst@vendettacd.io", role="analyst")); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("analyst@vendettacd.io"))
    assert client.post(f"/clients/{c.id}/sla", data={"sla_profile": "standard"}).status_code == 403
    assert SessionLocal().get(Client, c.id).sla_profile == "priority"  # unchanged
