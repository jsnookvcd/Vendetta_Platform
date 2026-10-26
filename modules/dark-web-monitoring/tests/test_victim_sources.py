"""Phase 2: scheduling and the victim feeds. The ransomware.live PRO client,
ransomwatch as an archived backfill, onion source seeding and disable rules, the
crawl's ordering and wall-clock cap, the direct capture queue, priority groups,
the profile editor and broken-profile detection, and the freshness rule.

No test touches the network. The PRO API is replaced with httpx.MockTransport
serving fixtures under tests/fixtures/ built from the documented response
shapes (see the comment at the top of app/ransomware_live.py); Tor fetches are
replaced with callables returning FetchResult."""
import datetime as dt
import json
from pathlib import Path

import httpx
import pytest

from app import auth, captures, connectors, fetch, onion_sources, priority, profile_store, readiness, worker
from app import ransomware_live as rl
from app.collectors import leak_feeds, onion_crawl
from app.config import settings
from app.db import (Capture, Client, CollectorRun, Evidence, Item, ParserProfile, PriorityGroup, RunRequest,
                    SessionLocal, Source, User, WatchTerm, utcnow)
from app.fetch import FetchResult
from app.pipeline import ingest

FIX = Path(__file__).parent / "fixtures"
AKIRA = "akiraexamplefixtureaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
AKIRA_MIRROR = "akiramirrorfixturecccccccccccccccccccccccccccccccccccccccccc.onion"


def _fixture(name):
    return json.loads((FIX / name).read_text())


def _db():
    return SessionLocal()


@pytest.fixture()
def pro_key(monkeypatch):
    monkeypatch.setattr(settings, "ransomware_live_api_key", "SECRET-PRO-KEY")


@pytest.fixture()
def no_key(monkeypatch):
    monkeypatch.setattr(settings, "ransomware_live_api_key", "")


class Upstream:
    """A MockTransport stand-in for api-pro.ransomware.live that records requests."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.routes.get(request.url.path)
        if handler is None:
            return httpx.Response(404, json={"detail": "not found"})
        return handler(request) if callable(handler) else handler

    @property
    def paths(self):
        return [r.url.path for r in self.requests]


@pytest.fixture()
def upstream(monkeypatch):
    up = Upstream()
    real = httpx.Client

    def fake_client(use_tor, timeout=None, cookies=""):
        return real(transport=httpx.MockTransport(up), timeout=5)

    monkeypatch.setattr(fetch, "_client", fake_client)
    return up


def _ok(name):
    return httpx.Response(200, json=_fixture(name))


def _as(client, email, role):
    db = _db()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role=role, source="platform"))
            db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def _client_with_term(name="Acme Federal Credit Union", term="Acme Federal Credit Union", industry="credit union",
                      country="USA"):
    db = _db()
    try:
        c = Client(name=name, industry=industry, country=country)
        db.add(c)
        db.commit()
        db.add(WatchTerm(client_id=c.id, term=term, kind="brand", severity="high"))
        db.commit()
        return c.id
    finally:
        db.close()


def _onion(db, group, url, **kw):
    s = Source(name=f"{group} leak site", kind="onion", url=url, group_name=group, **kw)
    db.add(s)
    db.commit()
    return s


# ================================================================ ransomware.live PRO client
def test_pro_client_parses_recent_victims_fixture(fresh_db, pro_key, upstream):
    upstream.routes["/victims/recent"] = _ok("ransomware_live_victims_recent.json")
    db = _db()
    try:
        summary = leak_feeds.run_ransomware_live(db)
        assert summary == {"ok": True, "new": 3, "rows": 3}
        items = {i.title: i for i in db.query(Item).filter_by(kind="victim")}
        acme = items["akira: Acme Federal Credit Union"]
        assert acme.url.startswith(f"http://{AKIRA}/")  # post_url is the capture target
        assert acme.published_at.date() == dt.date(2026, 10, 15)
        assert acme.meta["activity"] == "Financial Services" and acme.meta["country"] == "US"
        assert items["qilin: Example Tooling Works"].url == ""  # empty post_url
        src = db.query(Source).filter_by(kind="feed").one()
        assert src.url == "https://api-pro.ransomware.live/victims/recent" and src.last_ok is not None
    finally:
        db.close()
    req = upstream.requests[0]
    assert req.url.host == "api-pro.ransomware.live" and req.url.path == "/victims/recent"
    assert req.headers["X-API-KEY"] == "SECRET-PRO-KEY"
    assert req.headers["User-Agent"] == settings.ransomware_live_user_agent
    assert "Vendetta" in req.headers["User-Agent"]


def test_without_key_connector_is_off_and_v2_is_never_called(fresh_db, no_key, upstream, monkeypatch):
    # RansomLook is the keyless fallback for seeding; turn it off so this test
    # proves only that the ransomware.live v2 tier is never called.
    monkeypatch.setattr(settings, "ransomlook_enabled", False)
    db = _db()
    try:
        ok, reason = connectors.get("ransomware_live").configured(db)
        assert ok is False and "free PRO key from my.ransomware.live" in reason
        out = leak_feeds.run_ransomware_live(db)
        assert out["ok"] is False and out["error"] == rl.NOT_CONFIGURED
        assert "not configured: needs a free PRO key from my.ransomware.live" in out["error"]
        assert onion_sources.seed(db)["ok"] is False
    finally:
        db.close()
    assert upstream.requests == []
    assert connectors.get("ransomware_live").probes() == []
    with pytest.raises(rl.NotConfigured):
        rl.Client()
    assert "api.ransomware.live/v2" not in Path(rl.__file__).read_text().split('"""', 2)[2]


@pytest.mark.parametrize("status", [401, 403])
def test_pro_client_auth_failure(fresh_db, pro_key, upstream, status):
    upstream.routes["/victims/recent"] = httpx.Response(status, json={"detail": "Invalid API key"})
    db = _db()
    try:
        out = leak_feeds.run_ransomware_live(db)
    finally:
        db.close()
    assert out["ok"] is False and f"HTTP {status}" in out["error"] and "refused" in out["error"]
    assert "SECRET-PRO-KEY" not in out["error"]
    run = worker.run_job("ransomware_live", lambda d: out)
    assert run.ok is False


def test_pro_client_honours_retry_after_on_429(fresh_db, pro_key, upstream):
    responses = [httpx.Response(429, headers={"Retry-After": "7"}),
                 _ok("ransomware_live_victims_recent.json")]
    upstream.routes["/victims/recent"] = lambda req: responses.pop(0)
    slept = []
    client = rl.Client(sleep=slept.append)
    rows = client.recent_victims()
    assert len(rows) == 3 and slept == [7.0]
    assert upstream.paths == ["/victims/recent", "/victims/recent"]


def test_pro_client_gives_up_after_repeated_429(fresh_db, pro_key, upstream):
    upstream.routes["/victims/recent"] = httpx.Response(429, headers={"Retry-After": "120"})
    slept = []
    db = _db()
    try:
        out = leak_feeds.run_ransomware_live(db, client=rl.Client(sleep=slept.append))
    finally:
        db.close()
    assert out["ok"] is False and "429" in out["error"]
    assert slept == [120.0] * rl.RETRIES_ON_429
    assert len(upstream.requests) == rl.RETRIES_ON_429 + 1


def test_retry_after_is_capped_and_parses_http_dates():
    assert rl._retry_after_seconds("99999") == rl.MAX_RETRY_AFTER_SECONDS
    assert rl._retry_after_seconds(None) == rl.DEFAULT_RETRY_AFTER_SECONDS
    assert rl._retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0


@pytest.mark.parametrize("payload", [{"data": "maintenance"}, {"victims": [{"name": "x", "gang": "y"}]}, "oops"])
def test_pro_client_reports_schema_drift(fresh_db, pro_key, upstream, payload):
    upstream.routes["/victims/recent"] = httpx.Response(200, json=payload)
    db = _db()
    try:
        out = leak_feeds.run_ransomware_live(db)
        assert out["ok"] is False
        assert "schema" in out["error"] or "expected" in out["error"]
        assert db.query(Item).count() == 0
    finally:
        db.close()


def test_one_call_per_endpoint_per_run(fresh_db, pro_key, upstream):
    upstream.routes["/victims/recent"] = _ok("ransomware_live_victims_recent.json")
    upstream.routes["/groups"] = _ok("ransomware_live_groups.json")
    client = rl.Client()
    client.recent_victims()
    client.recent_victims()
    client.groups()
    client.groups()
    assert upstream.paths == ["/victims/recent", "/groups"]


# ================================================================ ransomwatch: archived backfill
def test_ransomwatch_is_never_scheduled():
    c = connectors.get("ransomwatch")
    assert c.scheduled is False and c.archived is True and c.live_feed is False
    ids = {j.id for j in worker.build_scheduler().get_jobs()}
    assert "ransomwatch" not in ids


def test_ransomwatch_backfill_is_admin_only_and_one_time(client, monkeypatch):
    _as(client, "analyst@vendettacd.io", "analyst")
    assert client.post("/connectors/ransomwatch/backfill", follow_redirects=False).status_code == 403
    assert client.post("/connectors/ransomwatch/run", follow_redirects=False).status_code == 400
    r = client.get("/connectors")
    assert "admin backfill" in r.text and "/connectors/ransomwatch/backfill" not in r.text
    _as(client, "board@vendettacd.io", "viewer")
    assert client.post("/connectors/ransomwatch/backfill", follow_redirects=False).status_code == 403

    client.cookies.clear()
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    r = client.get("/connectors")
    assert 'action="/connectors/ransomwatch/backfill"' in r.text
    assert client.post("/connectors/ransomwatch/backfill", follow_redirects=False).status_code == 302
    client.post("/connectors/ransomwatch/backfill", follow_redirects=False)
    db = _db()
    try:
        reqs = db.query(RunRequest).all()
        assert len(reqs) == 1 and reqs[0].payload == {"connector": "ransomwatch"}
    finally:
        db.close()

    posts = [{"post_title": "Old Victim Co", "group_name": "lockbit2", "discovered": "2025-06-16 01:00:00"}]
    monkeypatch.setattr(leak_feeds, "fetch_json", lambda url, **kw: posts)
    assert worker.poll_requests() == 1
    db = _db()
    try:
        run = db.query(CollectorRun).filter_by(job_id="ransomwatch").one()
        assert run.ok is True and run.trigger == "manual" and run.items_new == 1
        src = db.query(Source).filter(Source.url.ilike("%ransomwatch%")).one()
        assert src.enabled is False and src.meta["archived"] is True and src.meta["backfilled_at"]
        row = {r["key"]: r for r in connectors.status(db)}["ransomwatch"]
        assert row["state"] == "archived" and row["stale"] is False  # never live green, never stale
    finally:
        db.close()
    assert client.post("/connectors/ransomwatch/backfill", follow_redirects=False).status_code == 409
    assert "backfilled" in client.get("/connectors").text


# ================================================================ onion sources
def _seed_routes(up):
    up.routes["/groups"] = _ok("ransomware_live_groups.json")
    up.routes["/groups/akira"] = _ok("ransomware_live_group_akira.json")
    up.routes["/groups/qilin"] = httpx.Response(200, json={"group": "qilin", "lastseen": "2026-10-14",
                                                           "locations": []})
    up.routes["/groups/lockbit2"] = httpx.Response(200, json={"group": "lockbit2", "lastseen": "2022-06-01",
                                                              "locations": [{"fqdn": "lockbit2deadfixture.onion",
                                                                             "slug": "http://lockbit2deadfixture.onion/",
                                                                             "available": False, "type": "DLS"}]})
    up.routes["/groups/0mega"] = httpx.Response(200, json={"group": "0mega", "locations": None})


def test_seeding_from_group_locations(fresh_db, pro_key, upstream):
    _seed_routes(upstream)
    now = dt.datetime(2026, 10, 17, 12, 0, tzinfo=dt.timezone.utc)
    db = _db()
    try:
        feed = Source(name="ransomware.live recent victims", kind="feed",
                      url="https://api-pro.ransomware.live/victims/recent")
        db.add(feed)
        db.commit()
        db.add(Item(source_id=feed.id, kind="victim", title="akira: x", group_name="akira", content_hash="a" * 64,
                    published_at=dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)))
        db.commit()
        out = onion_sources.seed(db, now=now, sleep=lambda s: None)
        assert out["ok"] is True
        assert upstream.paths[0] == "/groups"
        assert upstream.paths[1] == "/groups/akira"  # active in the feed: first
        assert sorted(upstream.paths[1:]) == ["/groups/0mega", "/groups/akira", "/groups/lockbit2", "/groups/qilin"]
        assert len(upstream.paths) == len(set(upstream.paths))  # one call per endpoint
        srcs = {onion_sources.fqdn_of(s.url): s for s in db.query(Source).filter_by(kind="onion")}
        assert set(srcs) == {AKIRA, AKIRA_MIRROR, "lockbit2deadfixture.onion"}  # Chat and seized skipped
        live = srcs[AKIRA]
        assert live.enabled is True and live.group_name == "akira"
        assert live.meta["seeded_from"] == "ransomware.live" and live.meta["seeded_at"] == now.isoformat()
        assert live.meta["last_seen_in_feed"].startswith("2026-10-15")
        assert live.meta["group_lastseen"].startswith("2026-10-15")
        assert live.meta["available"] is True and live.meta["type"] == "DLS"
        mirror = srcs[AKIRA_MIRROR]
        assert mirror.enabled is False and mirror.meta["disabled"]["code"] == "unavailable"
        dead = srcs["lockbit2deadfixture.onion"]
        assert dead.enabled is False
    finally:
        db.close()


def test_seeding_reenables_a_migrated_mirror_ransomware_live_lists_as_live(fresh_db, pro_key, upstream):
    _seed_routes(upstream)
    db = _db()
    try:
        old = _onion(db, "akira", f"http://{AKIRA}/", meta={"seeded_from": "ransomwatch"})
        manual = _onion(db, "akira", f"http://{AKIRA_MIRROR}/", meta={"seeded_from": "ransomwatch"})
        assert onion_sources.migrate_ransomwatch_mirrors(db) == 2
        onion_sources.set_enabled_by_person(manual, False, "analyst@vendettacd.io")
        db.commit()
        onion_sources.seed(db, sleep=lambda s: None, now=dt.datetime(2026, 10, 17, tzinfo=dt.timezone.utc))
        db.refresh(old)
        db.refresh(manual)
        assert old.enabled is True and old.meta["seeded_from"] == "ransomware.live"
        assert old.meta["previously_seeded_from"] == "ransomwatch"
        assert manual.enabled is False and manual.meta["disabled"]["code"] == "manual"
        assert db.query(Source).filter_by(kind="onion", group_name="akira").count() == 2  # updated in place
    finally:
        db.close()


def test_disable_rules(fresh_db):
    now = dt.datetime(2026, 10, 17, tzinfo=dt.timezone.utc)
    db = _db()
    try:
        failing = _onion(db, "a", "http://a.onion/", fail_count=10, last_error="timed out",
                         meta={"seeded_from": "ransomware.live", "last_seen_in_feed": "2026-10-16T00:00:00+00:00"})
        idle = _onion(db, "b", "http://b.onion/", meta={"seeded_from": "ransomware.live",
                                                        "last_seen_in_feed": "2026-03-01T00:00:00+00:00"})
        fresh = _onion(db, "c", "http://c.onion/", meta={"seeded_from": "ransomware.live",
                                                         "last_seen_in_feed": "2026-09-01T00:00:00+00:00"})
        unseen_old = _onion(db, "d", "http://d.onion/", meta={"seeded_from": "ransomware.live",
                                                              "seeded_at": "2026-01-01T00:00:00+00:00"})
        unseen_new = _onion(db, "e", "http://e.onion/", meta={"seeded_from": "ransomware.live",
                                                              "seeded_at": "2026-10-01T00:00:00+00:00"})
        manual = _onion(db, "f", "http://f.onion/", meta={"seeded_from": "manual"})
        nine = _onion(db, "g", "http://g.onion/", fail_count=9, meta={"seeded_from": "ransomware.live",
                                                                      "group_lastseen": "2026-10-10"})
        out = onion_sources.apply_disable_rules(db, now)
        assert out == {"failures": 1, "inactive": 2}
        for s in (failing, idle, fresh, unseen_old, unseen_new, manual, nine):
            db.refresh(s)
        assert not failing.enabled and failing.meta["disabled"]["code"] == "failures"
        assert "10 consecutive" in failing.meta["disabled"]["detail"]
        assert not idle.enabled and idle.meta["disabled"]["code"] == "inactive"
        assert "2026-03-01" in idle.meta["disabled"]["detail"]
        assert not unseen_old.enabled
        assert fresh.enabled and unseen_new.enabled and manual.enabled and nine.enabled

        # A person re-enables on the Sources page; the inactivity rule leaves it for a full window.
        onion_sources.set_enabled_by_person(idle, True, "analyst@vendettacd.io")
        db.commit()
        onion_sources.apply_disable_rules(db, now + dt.timedelta(days=1))
        db.refresh(idle)
        assert idle.enabled and "disabled" not in idle.meta and idle.meta["reenabled_by"] == "analyst@vendettacd.io"
    finally:
        db.close()


def test_sources_page_shows_reason_and_reenables(admin):
    db = _db()
    try:
        s = _onion(db, "b", "http://b.onion/", meta={"seeded_from": "ransomware.live"})
        onion_sources.disable(s, "inactive", "no feed activity for b since 2026-03-01")
        db.commit()
        sid = s.id
    finally:
        db.close()
    r = admin.get("/sources")
    assert "off: inactive" in r.text and "no feed activity for b since 2026-03-01" in r.text
    admin.post(f"/sources/{sid}/toggle", follow_redirects=False)
    db = _db()
    try:
        s = db.get(Source, sid)
        assert s.enabled is True and "disabled" not in s.meta and s.meta["reenabled_by"] == "admin"
    finally:
        db.close()


def test_startup_migration_disables_ransomwatch_mirrors_once_and_never_deletes(fresh_db):
    db = _db()
    try:
        for i in range(3):
            _onion(db, f"g{i}", f"http://rw{i}.onion/", meta={"seeded_from": "ransomwatch", "available": True})
        keep = _onion(db, "akira", "http://keep.onion/", meta={"seeded_from": "ransomware.live"})
        db.add(Source(name="ransomwatch posts", kind="feed", url=leak_feeds.RANSOMWATCH_POSTS))
        db.commit()
        assert onion_sources.migrate_ransomwatch_mirrors(db) == 3
        rows = db.query(Source).filter_by(kind="onion").all()
        assert len(rows) == 4
        rw = [s for s in rows if s.meta.get("seeded_from") == "ransomwatch"]
        assert all(not s.enabled and s.meta["disabled"]["code"] == "ransomwatch_archive" for s in rw)
        db.refresh(keep)
        assert keep.enabled
        feed = db.query(Source).filter_by(kind="feed").one()
        assert feed.meta["archived"] is True and feed.enabled is False

        onion_sources.set_enabled_by_person(rw[0], True, "admin")
        db.commit()
        assert onion_sources.migrate_ransomwatch_mirrors(db) == 0  # idempotent
        db.refresh(rw[0])
        assert rw[0].enabled is True
    finally:
        db.close()


def test_worker_startup_runs_migration(fresh_db):
    db = _db()
    try:
        _onion(db, "x", "http://x.onion/", meta={"seeded_from": "ransomwatch"})
    finally:
        db.close()
    worker.phase2_startup()
    worker.phase2_startup()
    db = _db()
    try:
        assert db.query(Source).filter_by(kind="onion", enabled=False).count() == 1
    finally:
        db.close()


# ================================================================ crawl order and wall-clock cap
def test_crawl_orders_priority_then_activity(fresh_db):
    db = _db()
    try:
        _onion(db, "quiet", "http://quiet.onion/", meta={"last_seen_in_feed": "2026-05-01T00:00:00+00:00"})
        _onion(db, "busy", "http://busy.onion/", meta={"last_seen_in_feed": "2026-10-16T00:00:00+00:00"})
        _onion(db, "unknown", "http://unknown.onion/")
        _onion(db, "pinned", "http://pinned.onion/")
        priority.set_flags(db, "pinned", "admin", pinned=True)
        srcs = db.query(Source).filter_by(kind="onion").all()
        order = onion_sources.crawl_order(db, srcs)
        assert [s.group_name for s, _ in order] == ["pinned", "busy", "quiet", "unknown"]
        assert [p for _, p in order] == [True, False, False, False]
    finally:
        db.close()


def test_onion_crawl_stops_at_wall_clock_budget(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "onion_crawl_budget_minutes", 45)
    db = _db()
    try:
        for i in range(10):
            _onion(db, f"g{i}", f"http://g{i}.onion/")
        crawled = []
        t = {"now": 0.0}

        def fake_crawl(db_, src):
            crawled.append(src.url)
            t["now"] += 10 * 60  # each source takes ten minutes
            return True

        monkeypatch.setattr(onion_crawl, "crawl_source", fake_crawl)
        out = onion_crawl.run(db, clock=lambda: t["now"], sleep=lambda s: None)
        assert len(crawled) == 5 and out["attempted"] == 5
        assert out["budget_exhausted"] is True and out["ok"] is True
    finally:
        db.close()


def test_onion_crawl_count_cap_does_not_limit_priority_groups(fresh_db, monkeypatch):
    monkeypatch.setattr(onion_crawl, "MAX_SOURCES_PER_RUN", 2)
    db = _db()
    try:
        for i in range(3):
            _onion(db, "pin", f"http://pin{i}.onion/")
        for i in range(4):
            _onion(db, f"other{i}", f"http://other{i}.onion/")
        priority.set_flags(db, "pin", "admin", pinned=True)
        crawled = []
        monkeypatch.setattr(onion_crawl, "crawl_source", lambda d, s: crawled.append(s.group_name) or True)
        out = onion_crawl.run(db, sleep=lambda s: None)
        assert crawled[:3] == ["pin", "pin", "pin"] and len(crawled) == 5
        assert out["priority_attempted"] == 3
    finally:
        db.close()


# ================================================================ capture queue
def _victim_hit(db, url=f"http://{AKIRA}/acmefcu-example", group="akira"):
    feed = db.query(Source).filter_by(kind="feed").first()
    if feed is None:
        feed = Source(name="ransomware.live recent victims", kind="feed",
                      url="https://api-pro.ransomware.live/victims/recent")
        db.add(feed)
        db.commit()
    item, hits = ingest(db, kind="victim", title=f"{group}: Acme Federal Credit Union",
                        body="Victim: Acme Federal Credit Union", url=url, group_name=group, source=feed,
                        meta={"victim": "Acme Federal Credit Union"}, hash_parts=("victim", group, url))
    assert hits
    return item, hits[0]


def _res(url, html="<html><body>Acme Federal Credit Union data leak</body></html>", status=200, error=""):
    return FetchResult(url=url, status=status, content=html.encode(), headers={"content-type": "text/html"},
                       text=html, error=error)


@pytest.fixture()
def evidence_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_bucket", "")
    monkeypatch.setattr(settings, "evidence_local_dir", str(tmp_path))
    return tmp_path


def test_ingest_queues_capture_and_never_fetches_inline(fresh_db, monkeypatch):
    _client_with_term()

    def boom(*a, **kw):
        raise AssertionError("ingest must not fetch")

    from app import evidence
    monkeypatch.setattr(evidence, "fetch", boom)
    monkeypatch.setattr(evidence, "preserve", boom)
    monkeypatch.setattr(captures, "fetch", boom)
    monkeypatch.setattr(onion_sources, "fetch", boom)
    db = _db()
    try:
        item, hit = _victim_hit(db)
        cap = db.query(Capture).one()
        assert cap.hit_id == hit.id and cap.client_id == hit.client_id and cap.item_id == item.id
        assert cap.status == "pending" and cap.attempts == 0 and cap.next_attempt_at is not None
        assert cap.target_url == f"http://{AKIRA}/acmefcu-example" and cap.victim == "Acme Federal Credit Union"
        assert db.query(Evidence).count() == 0
    finally:
        db.close()


def test_capture_lifecycle_pending_to_captured(fresh_db, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        item, hit = _victim_hit(db)
        fetched = []
        out = captures.drain(db, fetcher=lambda u: fetched.append(u) or _res(u))
        assert out["attempted"] == 1 and out["captured"] == 1 and out["queue_depth"] == 0
        cap = db.query(Capture).one()
        assert cap.status == "captured" and cap.attempts == 1 and cap.captured_url == fetched[0]
        ev = db.get(Evidence, cap.evidence_id)
        assert ev.client_id == hit.client_id and ev.item_id == item.id and len(ev.sha256) == 64
        assert hit.id in ev.note and ev.captured_by == "capture-queue"
        assert (evidence_dir / "captures").exists()
        assert captures.drain(db, fetcher=lambda u: pytest.fail("nothing is due"))["attempted"] == 0
    finally:
        db.close()


def test_capture_retries_across_mirrors(fresh_db, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        _onion(db, "akira", f"http://{AKIRA}/", last_ok=utcnow())
        _onion(db, "akira", f"http://{AKIRA_MIRROR}/")
        _victim_hit(db)
        tried = []

        def fetcher(u):
            tried.append(u)
            return _res(u) if AKIRA_MIRROR in u else _res(u, status=0, error="SOCKS timeout")

        captures.drain(db, fetcher=fetcher)
        cap = db.query(Capture).one()
        assert tried == [f"http://{AKIRA}/acmefcu-example", f"http://{AKIRA_MIRROR}/acmefcu-example"]
        assert cap.status == "captured" and cap.captured_url == f"http://{AKIRA_MIRROR}/acmefcu-example"
    finally:
        db.close()


def test_capture_backs_off_then_is_unavailable_after_last_attempt(fresh_db, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        _victim_hit(db)
        down = lambda u: _res(u, status=0, error="connection refused")  # noqa: E731
        now = utcnow()
        captures.drain(db, now=now, fetcher=down)
        cap = db.query(Capture).one()
        assert cap.status == "pending" and cap.attempts == 1
        assert cap.next_attempt_at == now + dt.timedelta(hours=1)
        assert captures.drain(db, now=now + dt.timedelta(minutes=30), fetcher=down)["attempted"] == 0
        t = now
        for hours in captures.BACKOFF_HOURS:
            t = t + dt.timedelta(hours=hours)
            captures.drain(db, now=t, fetcher=down)
        db.refresh(cap)
        assert cap.status == "unavailable" and cap.attempts == captures.MAX_ATTEMPTS
        assert t - now == dt.timedelta(hours=24)
        assert "connection refused" in cap.last_error and cap.next_attempt_at is None
        assert db.query(Evidence).count() == 0
    finally:
        db.close()


def test_capture_from_index_without_victim_name(fresh_db, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        _onion(db, "akira", f"http://{AKIRA}/")
        _victim_hit(db, url="")  # the feed gave no post URL: target the group's index
        cap = db.query(Capture).one()
        assert cap.target_url == ""
        assert captures.candidates(db, cap) == [(f"http://{AKIRA}/", "index")]
        captures.drain(db, fetcher=lambda u: _res(u, html="<html><body>Other Victim Inc</body></html>"))
        db.refresh(cap)
        assert cap.status == "captured_index_no_match" and cap.evidence_id
    finally:
        db.close()


def test_capture_from_index_with_victim_name(fresh_db, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        _onion(db, "akira", f"http://{AKIRA}/")
        _victim_hit(db, url="")
        captures.drain(db, fetcher=lambda u: _res(u, html=(FIX / "leak_index.html").read_text()))
        assert db.query(Capture).one().status == "captured"
    finally:
        db.close()


def test_capture_without_any_target_fails_with_reason(fresh_db):
    _client_with_term()
    db = _db()
    try:
        _victim_hit(db, url="")
        captures.drain(db, fetcher=lambda u: pytest.fail("no target to fetch"))
        cap = db.query(Capture).one()
        assert cap.attempts == 1 and "no target" in cap.last_error
    finally:
        db.close()


def test_hit_page_capture_status_and_capture_now(client, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        _, hit = _victim_hit(db)
        captures.drain(db, fetcher=lambda u: _res(u, status=0, error="timeout"))
        hid = hit.id
    finally:
        db.close()
    _as(client, "board@vendettacd.io", "viewer")
    r = client.get(f"/hits/{hid}")
    assert "Direct capture" in r.text and "pending" in r.text and "1 of 4" in r.text
    assert client.post(f"/hits/{hid}/capture", follow_redirects=False).status_code == 403
    _as(client, "analyst@vendettacd.io", "analyst")
    assert client.post(f"/hits/{hid}/capture", follow_redirects=False).status_code == 302
    db = _db()
    try:
        cap = db.query(Capture).one()
        assert cap.status == "pending" and cap.attempts == 0 and cap.requested_by == "analyst@vendettacd.io"
    finally:
        db.close()


def test_connectors_page_shows_capture_queue_depth_and_success(admin, evidence_dir):
    _client_with_term()
    db = _db()
    try:
        _victim_hit(db)
        _victim_hit(db, url="http://other.onion/x")
        caps = db.query(Capture).order_by(Capture.created_at).all()
        captures.attempt(db, caps[0], fetcher=lambda u: _res(u))
        stats = captures.stats(db)
        assert stats["capture_queue_depth"] == 1 and stats["capture_success_rate"] == 1.0
        row = {r["key"]: r for r in connectors.status(db)}["captures"]
        assert row["capture_queue_depth"] == 1
    finally:
        db.close()
    r = admin.get("/connectors")
    assert "Direct capture queue" in r.text and "queue 1; success 100%" in r.text


# ================================================================ priority groups
def _victims(db, group, n, activity, country, days_ago=5):
    feed = db.query(Source).filter(Source.url.ilike("%ransomware.live%")).first()
    if feed is None:
        feed = Source(name="ransomware.live recent victims", kind="feed",
                      url="https://api-pro.ransomware.live/victims/recent")
        db.add(feed)
        db.commit()
    for i in range(n):
        db.add(Item(source_id=feed.id, kind="victim", title=f"{group}: v{i}", group_name=group,
                    content_hash=Item.make_hash(group, str(i), activity, str(days_ago)),
                    published_at=utcnow() - dt.timedelta(days=days_ago),
                    meta={"activity": activity, "country": country}))
    db.commit()


def test_priority_ranking_weights_client_industry_and_country(fresh_db, monkeypatch):
    db = _db()
    try:
        db.add(Client(name="Acme FCU", industry="Credit Union", country="USA"))
        db.add(Client(name="Dormant", industry="Healthcare", country="CA", active=False))
        db.commit()
        _victims(db, "akira", 5, "Financial Services", "US")  # 5 x (1 + 1 + 0.5) = 12.5
        _victims(db, "qilin", 8, "Education", "DE")             # 8 x 1 = 8
        _victims(db, "play", 6, "Healthcare", "CA")             # inactive client: 6
        _victims(db, "lockbit2", 40, "Financial Services", "US", days_ago=200)  # outside 90 days
        out = priority.compute(db)
        assert out["victims_considered"] == 19
        rows = {r.group_key: r for r in db.query(PriorityGroup)}
        assert rows["akira"].score == 12.5 and rows["akira"].matched_victims == 5 and rows["akira"].rank == 1
        assert rows["qilin"].rank == 2 and rows["play"].rank == 3
        assert "lockbit2" not in rows
        assert priority.priority_keys(db) == ["akira", "qilin", "play"]

        monkeypatch.setattr(settings, "priority_group_count", 2)
        priority.compute(db)
        assert priority.priority_keys(db) == ["akira", "qilin"]
    finally:
        db.close()


def test_priority_pins_and_exclusions_survive_refresh(fresh_db):
    db = _db()
    try:
        _victims(db, "akira", 5, "Manufacturing", "US")
        _victims(db, "qilin", 3, "Manufacturing", "US")
        priority.compute(db)
        priority.set_flags(db, "medusa", "admin", pinned=True)  # no recent victims, pinned anyway
        priority.set_flags(db, "akira", "admin", excluded=True)
        priority.compute(db)
        assert priority.priority_keys(db) == ["medusa", "qilin"]
        rows = {r.group_key: r for r in db.query(PriorityGroup)}
        assert rows["akira"].excluded and not rows["akira"].computed and rows["akira"].victims_90d == 5
        assert rows["medusa"].pinned
    finally:
        db.close()


def test_priority_refresh_is_scheduled_daily():
    job = {j.id: j for j in worker.build_scheduler().get_jobs()}["priority_refresh"]
    assert job.trigger.interval == dt.timedelta(hours=24) and job.next_run_time is not None


def test_priority_groups_page_and_admin_only_flags(client):
    db = _db()
    try:
        _victims(db, "akira", 5, "Manufacturing", "US")
        priority.compute(db)
    finally:
        db.close()
    _as(client, "analyst@vendettacd.io", "analyst")
    r = client.get("/priority-groups")
    assert r.status_code == 200 and "akira" in r.text and "computed" in r.text and ">none<" in r.text
    assert client.post("/priority-groups/akira/flag/pin", follow_redirects=False).status_code == 403
    client.cookies.clear()
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    assert client.post("/priority-groups/akira/flag/exclude", follow_redirects=False).status_code == 302
    assert client.post("/priority-groups/add", data={"group": "Medusa"}, follow_redirects=False).status_code == 302
    db = _db()
    try:
        assert db.get(PriorityGroup, "akira").excluded is True
        assert db.get(PriorityGroup, "medusa").pinned is True
    finally:
        db.close()
    assert "pinned" in client.get("/priority-groups").text


# ================================================================ profiles
SELECTORS = {"list_selector": "div.card", "title_selector": "h2.company", "link_selector": "a",
             "desc_selector": "p.desc", "date_selector": "span.date"}


def _stored_page(db, group="akira"):
    html = (FIX / "leak_index.html").read_text()
    src = _onion(db, group, f"http://{AKIRA}/")
    db.add(Item(source_id=src.id, kind="page", title=f"{group} index", body="text", url=src.url, group_name=group,
                content_hash=Item.make_hash("page", group), meta={"html": html}))
    db.commit()
    return src


def test_profile_preview_against_stored_page_then_save(admin):
    db = _db()
    try:
        src_id = _stored_page(db).id
    finally:
        db.close()
    r = admin.get("/priority-groups/akira/profile")
    assert r.status_code == 200 and "Enter selectors and press Preview" in r.text
    r = admin.post("/priority-groups/akira/profile", data={**SELECTORS, "action": "preview"})
    assert r.status_code == 200
    for name in ("Acme Federal Credit Union", "Example Logistics Group", "Fixture Dental Partners"):
        assert name in r.text
    assert f"http://{AKIRA}/acmefcu-example" in r.text and "3 entries" in r.text
    db = _db()
    try:
        assert db.query(ParserProfile).count() == 0  # preview never saves
    finally:
        db.close()
    r = admin.post("/priority-groups/akira/profile", data={**SELECTORS, "action": "save", "apply": "on"},
                   follow_redirects=False)
    assert r.status_code == 302
    db = _db()
    try:
        row = db.get(ParserProfile, "group-akira")
        assert row.state == "draft" and row.selectors["list_selector"] == "div.card"
        assert db.get(Source, src_id).profile == "group-akira"
        prof = profile_store.get(db, "group-akira")
        assert prof["kind"] == "leak" and prof["stored"] == "database"
        assert profile_store.state_for_group(db, "akira") == "draft"
    finally:
        db.close()


def test_profile_preview_with_no_matches_and_viewer_cannot_save(client):
    db = _db()
    try:
        _stored_page(db)
    finally:
        db.close()
    _as(client, "board@vendettacd.io", "viewer")
    assert client.get("/priority-groups/akira/profile").status_code == 200
    assert client.post("/priority-groups/akira/profile", data={**SELECTORS, "action": "save"},
                       follow_redirects=False).status_code == 403
    _as(client, "analyst@vendettacd.io", "analyst")
    r = client.post("/priority-groups/akira/profile", data={**SELECTORS, "list_selector": "li.none",
                                                            "action": "preview"})
    assert "extract no entries" in r.text


def test_yaml_profiles_still_load_as_fallback(fresh_db):
    db = _db()
    try:
        prof = profile_store.get(db, "_example_leak")
        assert prof["kind"] == "leak" and prof["stored"] == "yaml"
        assert profile_store.get(db, "nope") is None
    finally:
        db.close()


def test_broken_profile_detection(admin, monkeypatch):
    good = (FIX / "leak_index.html").read_text()
    redesigned = "<html><body><section class='new-layout'><b>Acme Federal Credit Union</b> and more text " \
                 "so the page is long enough to store as text.</section></body></html>"
    db = _db()
    try:
        src = _stored_page(db)
        profile_store.save(db, "akira", "akira", {**SELECTORS, "max_posts_per_run": 0}, "admin")
        sid = src.id
    finally:
        db.close()
    pages = [good, redesigned]
    monkeypatch.setattr(onion_sources, "fetch_onion", lambda url, cookies="": _res(url, html=pages.pop(0)))
    db = _db()
    try:
        assert onion_crawl.crawl_source(db, db.get(Source, sid)) is True
        assert db.get(ParserProfile, "group-akira").state == "working"
        assert db.query(Item).filter_by(kind="post").count() == 3
        onion_crawl.crawl_source(db, db.get(Source, sid))
        row = db.get(ParserProfile, "group-akira")
        assert row.state == "broken" and row.broken_at is not None and row.ever_extracted == 3
        assert db.get(Source, sid).meta["profile_state"] == "broken"
        assert [b["profile"] for b in profile_store.broken_profiles(db)] == ["group-akira"]
        # The generic fallback still stored the changed page so nothing is missed.
        assert db.query(Item).filter_by(kind="page").count() == 2
    finally:
        db.close()
    r = admin.get("/connectors")
    assert "Broken parser profiles" in r.text and "group-akira" in r.text
    assert "Parser profile extracts nothing now" in admin.get("/").text


def test_generic_crawl_keeps_html_for_the_editor(fresh_db, monkeypatch):
    html = (FIX / "leak_index.html").read_text()
    monkeypatch.setattr(onion_sources, "fetch_onion", lambda url, cookies="": _res(url, html=html))
    db = _db()
    try:
        src = _onion(db, "akira", f"http://{AKIRA}/")
        onion_crawl.crawl_source(db, src)
        page = profile_store.latest_page(db, "AKIRA")
        assert page is not None and "div class=\"card\"" in page.meta["html"]
        assert "window.tracking" not in page.body  # stored text never carries script
    finally:
        db.close()


def test_fetch_onion_falls_back_from_https_to_http(monkeypatch):
    seen = []

    def fake_fetch(url, force_tor=False, cookies=""):
        seen.append((url, force_tor))
        return _res(url) if url.startswith("http://") else _res(url, status=0, error="SSL: wrong version number")

    monkeypatch.setattr(onion_sources, "fetch", fake_fetch)
    res = onion_sources.fetch_onion(f"https://{AKIRA}/")
    assert res.ok and seen == [(f"https://{AKIRA}/", True), (f"http://{AKIRA}/", True)]


# ================================================================ freshness
def test_freshness_rule_consistent_on_page_and_readiness(fresh_db, pro_key):
    db = _db()
    try:
        src = Source(name="ransomware.live recent victims", kind="feed",
                     url="https://api-pro.ransomware.live/victims/recent")
        db.add(src)
        db.commit()
        db.add(Item(source_id=src.id, kind="victim", title="akira: fresh", content_hash="f" * 64,
                    published_at=utcnow() - dt.timedelta(days=2)))
        db.add(CollectorRun(job_id="ransomware_live", started_at=utcnow(), finished_at=utcnow(), ok=True))
        db.commit()
        row = {r["key"]: r for r in connectors.status(db)}["ransomware_live"]
        assert row["stale"] is False and row["state"] == "ok"
        assert readiness.integrations()["connectors"]["ransomware_live"]["stale"] is False
        later = utcnow() + dt.timedelta(days=6)
        assert {r["key"]: r for r in connectors.status(db, later)}["ransomware_live"]["stale"] is True
        assert connectors.STALE_DAYS == 7
    finally:
        db.close()
