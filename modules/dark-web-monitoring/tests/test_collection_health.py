"""Phase 1 collection health: the scheduler, the CollectorRun log, the worker
heartbeat and Tor status, the Connectors page, Run now, the dashboard banner,
readiness and the diagnose CLI. No test touches the network; upstreams are
replaced with httpx.MockTransport or monkeypatched callables."""
import dataclasses
import datetime as dt
import io

import httpx
import pytest

from app import auth, connectors, diagnose, fetch, health, readiness, worker
from app.collectors import leak_feeds
from app.config import settings
from app.db import CollectorRun, Item, RunRequest, SessionLocal, Source, User, utcnow
from app.pipeline import ingest


def _db():
    return SessionLocal()


def _runs(job_id=None):
    db = _db()
    try:
        q = db.query(CollectorRun)
        if job_id:
            q = q.filter_by(job_id=job_id)
        return q.order_by(CollectorRun.id).all()
    finally:
        db.close()


def _healthy_worker():
    db = _db()
    try:
        health.beat(db)
        health.record_tor(db, {"IsTor": True, "IP": "185.220.101.1"})
    finally:
        db.close()


def _as_viewer(client, email="board@vendettacd.io"):
    db = _db()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role="viewer", source="platform"))
            db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def _mock_http(monkeypatch, handler):
    real = httpx.Client

    def fake_client(use_tor, timeout=None, cookies=""):
        return real(transport=httpx.MockTransport(handler), timeout=5)

    monkeypatch.setattr(fetch, "_client", fake_client)


# ---------------------------------------------------------------- scheduler
def test_every_scheduled_job_has_a_next_run_time():
    """Regression for F1: a job added with next_run_time=None is paused forever."""
    sched = worker.build_scheduler()
    jobs = sched.get_jobs()
    assert jobs
    for job in jobs:
        assert job.next_run_time is not None, f"{job.id} would never run"
    ids = {j.id for j in jobs}
    assert {c.job_id for c in connectors.CONNECTORS} <= ids
    assert {"heartbeat", "tor_check", "run_requests", "retention", "seed"} <= ids
    assert {"ransomware_live", "ransomwatch"} <= ids


def test_scheduler_uses_registry_intervals_and_starts_feeds_soon():
    now = dt.datetime(2026, 10, 17, 12, 0, tzinfo=dt.timezone.utc)
    sched = worker.build_scheduler(now)
    by = {j.id: j for j in sched.get_jobs()}
    for c in connectors.CONNECTORS:
        assert by[c.job_id].trigger.interval == dt.timedelta(minutes=c.interval_minutes)
    assert by["ransomware_live"].next_run_time - now < dt.timedelta(minutes=1)
    assert by["onion_crawl"].next_run_time - now == dt.timedelta(minutes=settings.onion_crawl_interval)


def test_registry_keys_are_unique_and_complete():
    keys = [c.key for c in connectors.CONNECTORS]
    assert len(keys) == len(set(keys))
    assert set(keys) == {"ransomware_live", "ransomwatch", "onion_crawl", "forum_crawl", "hibp",
                         "ct_logs", "pastes", "telegram"}


# ---------------------------------------------------------------- CollectorRun
def test_collector_run_written_on_success(fresh_db):
    def job(db):
        ingest(db, kind="victim", title="lockbit: Acme", body="Victim: Acme", hash_parts=("t", "acme"))
        ingest(db, kind="victim", title="lockbit: Acme", body="Victim: Acme", hash_parts=("t", "acme"))  # duplicate
        return {"ok": True, "rows": 2}

    run = worker.run_job("unit", job)
    assert run.ok is True and run.finished_at is not None
    assert run.items_new == 1 and run.hits_new == 0
    assert run.detail == {"rows": 2}
    assert len(_runs("unit")) == 1


def test_collector_run_written_on_exception(fresh_db):
    def job(db):
        raise RuntimeError("upstream exploded")

    run = worker.run_job("unit", job)
    assert run.ok is False
    assert "upstream exploded" in run.error
    stored = _runs("unit")[0]
    assert stored.ok is False and stored.finished_at is not None


def test_collector_reporting_failure_is_a_failed_run(fresh_db):
    run = worker.run_job("unit", lambda db: {"ok": False, "error": "HTTP 403"})
    assert run.ok is False and run.error == "HTTP 403"


def test_unconfigured_connector_is_skipped_on_schedule_and_fails_on_request(fresh_db):
    check = lambda db: (False, "needs HIBP_API_KEY")  # noqa: E731
    assert worker.run_job("hibp", lambda db: None, check=check) is None
    assert _runs("hibp") == []
    run = worker.run_job("hibp", lambda db: None, check=check, trigger="manual", requested_by="admin")
    assert run.ok is False and "needs HIBP_API_KEY" in run.error


def test_ransomware_live_counts_items_through_mock_transport(fresh_db, monkeypatch):
    payload = [{"victim": "Acme Credit Union", "group": "akira", "attackdate": "2026-10-15 08:00:00",
                "website": "acmecu.org", "country": "US"}]
    _mock_http(monkeypatch, lambda req: httpx.Response(200, json=payload))
    run = worker.run_job("ransomware_live", leak_feeds.run_ransomware_live)
    assert run.ok is True and run.items_new == 1
    assert run.detail["new"] == 1


def test_ransomware_live_http_error_is_a_failed_run(fresh_db, monkeypatch):
    _mock_http(monkeypatch, lambda req: httpx.Response(403, text="Forbidden"))
    run = worker.run_job("ransomware_live", leak_feeds.run_ransomware_live)
    assert run.ok is False and "403" in run.error


def test_retention_prunes_runs_older_than_thirty_days(fresh_db):
    db = _db()
    try:
        db.add(CollectorRun(job_id="old", started_at=utcnow() - dt.timedelta(days=31), ok=True))
        db.add(CollectorRun(job_id="new", started_at=utcnow() - dt.timedelta(days=1), ok=True))
        db.commit()
    finally:
        db.close()
    worker.retention()
    assert [r.job_id for r in _runs()] == ["new"]


# ---------------------------------------------------------------- heartbeat and Tor
def test_heartbeat_persisted(fresh_db):
    db = _db()
    try:
        assert health.heartbeat_age_seconds(db) is None
    finally:
        db.close()
    worker.heartbeat()
    db = _db()
    try:
        age = health.heartbeat_age_seconds(db)
        assert age is not None and age < 5
        later = utcnow() + dt.timedelta(minutes=10)
        assert health.heartbeat_age_seconds(db, later) >= 600
    finally:
        db.close()


def test_tor_status_persisted(fresh_db, monkeypatch):
    monkeypatch.setattr(worker, "tor_check", lambda: {"IsTor": True, "IP": "185.220.101.1"})
    worker.check_tor()
    db = _db()
    try:
        t = health.tor_status(db)
        assert t["is_tor"] is True and t["reachable"] is True and t["exit_ip"] == "185.220.101.1"
        assert t["checked_at"]
    finally:
        db.close()
    monkeypatch.setattr(worker, "tor_check", lambda: {"IsTor": False, "error": "SOCKS connection refused"})
    worker.check_tor()
    db = _db()
    try:
        t = health.tor_status(db)
        assert t["is_tor"] is False and t["reachable"] is False and "refused" in t["error"]
    finally:
        db.close()


# ---------------------------------------------------------------- Connectors page
def test_connectors_page_renders_with_no_data(admin):
    r = admin.get("/connectors")
    assert r.status_code == 200
    for c in connectors.CONNECTORS:
        assert c.name in r.text
    assert "needs HIBP_API_KEY" in r.text or settings.hibp_api_key
    assert 'action="/connectors/ransomware_live/run"' in r.text
    assert "Worker heartbeat age" in r.text


def test_connectors_page_shows_failures(admin):
    _healthy_worker()
    db = _db()
    try:
        db.add(CollectorRun(job_id="ransomware_live", started_at=utcnow(), finished_at=utcnow(), ok=False,
                            error="HTTPStatusError: 403 Forbidden"))
        db.commit()
    finally:
        db.close()
    r = admin.get("/connectors")
    assert r.status_code == 200
    assert "403 Forbidden" in r.text
    assert "failed" in r.text


def _stale_feed():
    db = _db()
    try:
        src = Source(name="ransomware.live recent victims", kind="feed", url="https://api.ransomware.live/v2/recentvictims")
        db.add(src)
        db.commit()
        db.add(Item(source_id=src.id, kind="victim", title="old: victim", content_hash="x" * 64,
                    published_at=utcnow() - dt.timedelta(days=30)))
        db.add(CollectorRun(job_id="ransomware_live", started_at=utcnow(), finished_at=utcnow(), ok=True))
        db.commit()
    finally:
        db.close()


def test_connectors_page_flags_stale_feed(admin):
    _healthy_worker()
    _stale_feed()
    db = _db()
    try:
        row = {r["key"]: r for r in connectors.status(db)}["ransomware_live"]
        assert row["stale"] is True and row["state"] == "stale"
        assert row["items_7d"] == 1 and row["last_ok"] is not None
    finally:
        db.close()
    r = admin.get("/connectors")
    assert "stale" in r.text


def test_viewer_sees_connectors_but_cannot_run_now(client):
    _as_viewer(client)
    r = client.get("/connectors")
    assert r.status_code == 200
    assert "/connectors/ransomware_live/run" not in r.text
    r = client.post("/connectors/ransomware_live/run", follow_redirects=False)
    assert r.status_code == 403
    db = _db()
    try:
        assert db.query(RunRequest).count() == 0
    finally:
        db.close()


def test_run_now_queues_and_worker_drains(admin, monkeypatch):
    r = admin.post("/connectors/ransomware_live/run", follow_redirects=False)
    assert r.status_code == 302
    admin.post("/connectors/ransomware_live/run", follow_redirects=False)  # no duplicate while pending
    db = _db()
    try:
        reqs = db.query(RunRequest).all()
        assert len(reqs) == 1 and reqs[0].status == "pending" and reqs[0].requested_by == "admin"
        assert reqs[0].payload == {"connector": "ransomware_live"}
    finally:
        db.close()
    assert admin.post("/connectors/nope/run", follow_redirects=False).status_code == 404

    c = connectors.get("ransomware_live")
    monkeypatch.setitem(connectors._BY_KEY, "ransomware_live",
                        dataclasses.replace(c, job=lambda db: {"ok": True, "new": 0}))
    assert worker.poll_requests() == 1
    db = _db()
    try:
        req = db.query(RunRequest).one()
        assert req.status == "done" and req.finished_at is not None
        run = db.query(CollectorRun).filter_by(job_id="ransomware_live").one()
        assert run.trigger == "manual" and run.requested_by == "admin" and run.ok is True
        assert req.result["run_id"] == run.id
    finally:
        db.close()


# ---------------------------------------------------------------- dashboard banner
def test_dashboard_banner_red_without_worker(admin):
    r = admin.get("/")
    assert "health-banner red" in r.text
    assert "never reported a heartbeat" in r.text


def test_dashboard_banner_red_when_tor_down(admin):
    db = _db()
    try:
        health.beat(db)
        health.record_tor(db, {"IsTor": False, "error": "SOCKS connection refused"})
    finally:
        db.close()
    r = admin.get("/")
    assert "health-banner red" in r.text and "Tor is not exiting" in r.text


def test_dashboard_banner_amber_on_failed_connector(admin):
    _healthy_worker()
    db = _db()
    try:
        db.add(CollectorRun(job_id="ransomware_live", started_at=utcnow(), finished_at=utcnow(), ok=False, error="403"))
        db.commit()
    finally:
        db.close()
    r = admin.get("/")
    assert "health-banner amber" in r.text and "ransomware.live victims" in r.text


def test_dashboard_banner_amber_on_stale_feed(admin):
    _healthy_worker()
    _stale_feed()
    r = admin.get("/")
    assert "health-banner amber" in r.text and "No item published" in r.text


def test_no_banner_when_healthy(admin, monkeypatch):
    _healthy_worker()
    monkeypatch.setattr(connectors, "CONNECTORS",
                        [dataclasses.replace(c, check=lambda db: (False, "off for test")) for c in connectors.CONNECTORS])
    r = admin.get("/")
    assert "health-banner" not in r.text
    assert 'href="/connectors"' in r.text  # nav link


# ---------------------------------------------------------------- readiness
def test_readiness_block_shape(fresh_db):
    _healthy_worker()
    blk = readiness.block()
    for k in ("module", "enabled", "keys", "sso", "platform", "posture", "integrations"):
        assert k in blk
    integ = blk["integrations"]
    assert integ["kind"] == "collection-sources" and isinstance(integ["configured"], int)
    assert integ["tor"]["ok"] is True and integ["tor"]["checked_at"]
    assert isinstance(integ["worker_heartbeat_age_seconds"], int)
    assert set(integ["connectors"]) == {c.key for c in connectors.CONNECTORS}
    for v in integ["connectors"].values():
        assert {"configured", "reason", "last_ok", "stale", "error"} <= set(v)


def test_readiness_reports_tor_down_without_worker(fresh_db):
    integ = readiness.integrations()
    assert integ["tor"]["ok"] is False
    assert integ["worker_heartbeat_age_seconds"] is None


# ---------------------------------------------------------------- diagnose
def test_diagnose_prints_table_and_probes_without_secrets(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "SECRET-HIBP-KEY-123")
    monkeypatch.setattr(settings, "ransomware_live_api_key", "SECRET-RL-KEY-456")
    _healthy_worker()
    seen = []

    def fake_get(p):
        seen.append(p)
        if "crt.sh" in p.url:
            raise httpx.ConnectTimeout("timed out with SECRET-HIBP-KEY-123")
        return 200, 1234

    out = io.StringIO()
    code = diagnose.report(out=out, probe=True, get=fake_get)
    text = out.getvalue()
    assert "worker heartbeat age" in text and "is_tor=True" in text
    for c in connectors.CONNECTORS:
        assert c.key in text
    assert "200 1234B" in text and "ERR ConnectTimeout" in text
    assert "SECRET-HIBP-KEY-123" not in text and "SECRET-RL-KEY-456" not in text
    assert any(p.headers for p in seen)  # keys were sent to the probe, never printed
    assert code in (0, 1)


def test_diagnose_without_probe(fresh_db):
    out = io.StringIO()
    code = diagnose.report(out=out, probe=False, get=lambda p: pytest.fail("probe ran"))
    assert "connector | state" in out.getvalue()
    assert code == 1  # no heartbeat recorded
