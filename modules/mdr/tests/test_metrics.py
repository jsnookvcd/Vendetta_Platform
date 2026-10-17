"""MTTD, MTTA and MTTR math (pure) and the /api/metrics shape."""
import datetime as dt

from app import metrics
from app.db import Investigation, SessionLocal
from helpers import bearer, finding, ingest, make_client

T = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.timezone.utc)


def m(minutes):
    return T + dt.timedelta(minutes=minutes)


def rec(first, opened, ack=None, contained=None, closed=None, pid="p1", client="Acme"):
    return {"platform_client_id": pid, "client": client, "first_signal_at": m(first), "opened_at": m(opened),
            "acknowledged_at": m(ack) if ack is not None else None,
            "contained_at": m(contained) if contained is not None else None,
            "closed_at": m(closed) if closed is not None else None}


def test_percentiles():
    assert metrics.median([]) is None and metrics.percentile([], 90) is None
    assert metrics.median([3, 1, 2]) == 2 and metrics.median([1, 2, 3, 4]) == 2.5
    vals = list(range(1, 11))
    assert metrics.percentile(vals, 90) == 9 and metrics.percentile(vals, 100) == 10
    assert metrics.percentile([7], 90) == 7


def test_durations_follow_the_definitions():
    d = metrics.durations(rec(0, 4, ack=10, contained=64, closed=200))
    assert d == {"mttd": 4.0, "mtta": 6.0, "mttr": 60.0}
    # never contained: MTTR runs to close
    assert metrics.durations(rec(0, 4, ack=10, closed=124))["mttr"] == 120.0
    # still waiting: contributes nothing
    assert metrics.durations(rec(0, 4)) == {"mttd": 4.0, "mtta": None, "mttr": None}


def test_compute_summary_and_by_client():
    rs = [rec(0, 2, ack=5, contained=32), rec(0, 4, ack=14, closed=64), rec(0, 6),
          rec(0, 10, ack=11, contained=20, pid="p2", client="Bravo")]
    out = metrics.compute(rs, 30)
    assert out["window_days"] == 30 and out["investigations"] == 4
    assert out["mttd_minutes"]["median"] == 5.0 and out["mttd_minutes"]["p90"] == 10.0
    assert out["mtta_minutes"]["count"] == 3 and out["mtta_minutes"]["median"] == 3.0
    assert out["mttr_minutes"]["median"] == 30.0 and out["mttr_minutes"]["p90"] == 60.0
    by = {b["platform_client_id"]: b for b in out["by_client"]}
    assert by["p1"]["investigations"] == 3 and by["p1"]["client"] == "Acme"
    assert by["p2"]["mttr_minutes"]["median"] == 10.0


def test_fmt():
    assert metrics.fmt(None) == "n/a" and metrics.fmt(0.5) == "30s" and metrics.fmt(12) == "12m"
    assert metrics.fmt(150) == "2.5h" and metrics.fmt(60 * 72) == "3.0d"


def test_api_metrics_window_and_filter(client, now):
    make_client()
    make_client(name="Bravo", pid="plat-bravo", domains="bravo.example")
    ingest([finding(fid="a1", at=now - dt.timedelta(minutes=10)),
            finding(fid="b1", pid="plat-bravo", client="Bravo", at=now - dt.timedelta(minutes=2))], now=now)
    db = SessionLocal()
    acme = db.query(Investigation).filter_by(platform_client_id="plat-acme").one()
    acme.acknowledged_at = now + dt.timedelta(minutes=3)
    acme.contained_at = now + dt.timedelta(minutes=33)
    db.commit()
    body = client.get("/api/metrics", params={"days": 30}, headers=bearer()).json()
    assert set(body) >= {"window_days", "investigations", "mttd_minutes", "mtta_minutes", "mttr_minutes", "by_client"}
    assert body["investigations"] == 2 and body["mttd_minutes"]["median"] == 6.0
    one = client.get("/api/metrics", params={"platform_client_id": "plat-acme"}, headers=bearer()).json()
    assert one["investigations"] == 1 and one["mtta_minutes"]["median"] == 3.0
    assert one["mttr_minutes"]["median"] == 33.0 and one["by_client"][0]["client"] == "Acme Corp"
    # an investigation opened before the window is left out
    db = SessionLocal()
    acme = db.query(Investigation).filter_by(platform_client_id="plat-acme").one()
    acme.opened_at = now - dt.timedelta(days=40)
    db.commit()
    assert client.get("/api/metrics", params={"days": 30}, headers=bearer()).json()["investigations"] == 1
    assert client.get("/api/metrics").status_code == 401
