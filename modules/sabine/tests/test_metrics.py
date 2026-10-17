"""Mean Time to Trusted Action: a pure function over ledger rows, a cached
getter, and the numbers on the Overview, the board, the API and the daily
summary."""
import datetime as dt

from app import auth, brain, metrics
from app.db import Brief, SessionLocal

from test_brain import world  # noqa: F401  (fixture: mock platform and modules)

NOW = dt.datetime(2026, 10, 16, 12, 0, tzinfo=dt.timezone.utc)


def _row(kind, ref, minutes_ago, summary="", **detail):
    return {"at": NOW - dt.timedelta(minutes=minutes_ago), "kind": kind, "ref": ref, "summary": summary, "detail": detail}


def _auto(ref, raised, done):
    return [_row("proposal", ref, raised, f"x: {ref}"),
            _row("action", ref, done, f"x done: {ref}", autonomy="auto", result={"ok": True})]


def _human(ref, raised, decided, done, approve=True):
    rows = [_row("proposal", ref, raised, f"x: {ref}"),
            _row("decision", ref, decided, f"{'approved' if approve else 'rejected'}: {ref}")]
    if approve:
        rows.append(_row("action", ref, done, f"x done: {ref}", autonomy="approved", by="dan", result={"ok": True}))
    return rows


def test_compute_on_synthetic_rows():
    rows = []
    # five automatic actions at 10s, 20s, 30s, 40s, 50s after being raised
    for i, lat in enumerate((10, 20, 30, 40, 50)):
        rows += _auto(f"a{i}", 100 + lat / 60, 100)
    # three approved by a person: 4h, 8h, 30h; one rejected
    rows += _human("h1", 60 * 24, 60 * 20, 60 * 20)
    rows += _human("h2", 60 * 24, 60 * 16, 60 * 16)
    rows += _human("h3", 60 * 48, 60 * 18, 60 * 18)
    rows += _human("h4", 60 * 24, 60 * 10, 60 * 10, approve=False)
    # a failed auto action: counted as attempted, not as a latency
    rows += [_row("proposal", "f1", 50, "x: f1"), _row("action", "f1", 49, "x failed: f1", autonomy="auto", result={"ok": False})]
    # an auto action from 20 days ago: in the 30-day window only; its proposal was 10 days earlier
    rows += _auto("old", 60 * 24 * 20 + 5, 60 * 24 * 20)
    # ledger noise that is not a proposal decision
    rows += [_row("decision", "w1", 30, "claimed: something"), _row("cycle", "", 1, "cycle"), _row("observation", "", 2, "asked: hi")]
    m = metrics.compute(rows, now=NOW)
    w7, w30 = m["windows"][7], m["windows"][30]
    assert w7["proposals_raised"] == 10 and w30["proposals_raised"] == 11
    assert w7["auto"] == {"n": 6, "ok": 5, "median_s": 30.0, "p90_s": 50.0}
    assert w7["human"]["n"] == 3 and w7["human"]["ok"] == 3
    assert w7["human"]["median_s"] == 8 * 3600 and w7["human"]["p90_s"] == 30 * 3600
    assert w7["decided"] == 4 and w7["approved"] == 3 and w7["rejected"] == 1 and w7["approval_rate"] == 0.75
    assert w7["autonomous_share"] == 0.5  # 5 closed by SABINE out of 10 raised
    assert w30["auto"]["ok"] == 6 and w30["auto"]["p90_s"] == 300.0  # the old one: 5 minutes
    assert w30["autonomous_share"] == round(6 / 11, 3)
    # the line reads the numbers back
    line = metrics.line(m, 7)
    assert "10 proposals raised" in line and "30s automatic" in line and "8.0h with a person" in line
    assert "4 decided, 75% approved" in line and "50% closed without a person" in line
    # nothing raised: no division, a plain sentence
    empty = metrics.compute([], now=NOW)["windows"][7]
    assert empty["approval_rate"] is None and empty["autonomous_share"] is None and empty["auto"]["median_s"] is None
    assert "nothing to measure" in metrics.line(metrics.compute([], now=NOW))


def test_percentile_is_nearest_rank():
    assert metrics._pct([5.0], 0.9) == 5.0
    assert metrics._pct([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert metrics._pct([1.0, 2.0, 3.0, 4.0], 0.9) == 4.0
    assert metrics.fmt_seconds(5) == "5s" and metrics.fmt_seconds(125) == "2m" and metrics.fmt_seconds(7200) == "2.0h"
    assert metrics.fmt_seconds(2 * 86400) == "2.0d" and metrics.fmt_seconds(None) == "n/a"


def test_metrics_from_a_live_cycle_and_the_surfaces(client, world):  # noqa: F811
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    bearer = {"Authorization": f"Bearer {auth.api_token()}"}
    before = client.get("/api/metrics", headers=bearer).json()
    assert before["windows"]["7"]["proposals_raised"] == 0
    db = SessionLocal()
    brain.cycle(db)
    from app.db import Proposal
    e = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    brain.decide(db, e, "dan@vendettacd.io", True)
    h = db.query(Proposal).filter_by(key="host_action:al1").one()
    brain.decide(db, h, "dan@vendettacd.io", False, "not yet")
    m = metrics.get(db, ttl=0)["windows"][7]
    n_props = db.query(Proposal).count()
    assert m["proposals_raised"] == n_props and m["auto"]["ok"] >= 5 and m["auto"]["median_s"] is not None
    assert m["human"]["ok"] == 1 and m["decided"] == 2 and m["approval_rate"] == 0.5
    assert 0 < m["autonomous_share"] < 1
    # the cycle and the decision invalidate the cache, so the API agrees
    api = client.get("/api/metrics", headers=bearer).json()["windows"]["7"]
    assert api["decided"] == 2 and api["proposals_raised"] == n_props
    # overview block
    r = client.get("/")
    assert r.status_code == 200 and "Mean time to trusted action" in r.text and "50% approved" in r.text
    # the board carries the windows and the tile
    b = client.get("/api/board").json()
    assert b["metrics"]["7"]["decided"] == 2 and b["mtta"]["auto"].startswith("auto ") and "50% approved" in b["mtta"]["sub"]
    assert "Time to trusted action" in client.get("/board").text
    # the daily summary text carries the sentence
    s = db.query(Brief).filter_by(kind="daily-summary").one()
    assert "## How I am doing" in s.body_md and "Trusted action over 7 days" in s.body_md


def test_getter_caches_until_invalidated(world):  # noqa: F811
    db = SessionLocal()
    metrics.invalidate()
    a = metrics.get(db)
    brain.cycle(db)  # invalidates
    b = metrics.get(db)
    assert a["windows"][7]["proposals_raised"] == 0 and b["windows"][7]["proposals_raised"] > 0
    # a change without invalidation is served from the cache inside the ttl
    from app import ledger
    ledger.append(db, "proposal", "sabine", "x: p", {}, ref="zzz")
    assert metrics.get(db)["windows"][7]["proposals_raised"] == b["windows"][7]["proposals_raised"]
    assert metrics.get(db, ttl=0)["windows"][7]["proposals_raised"] == b["windows"][7]["proposals_raised"] + 1
