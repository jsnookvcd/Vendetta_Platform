"""Phase 3 live Tor search: engine adapters against HTML fixtures (including
Ahmia's rotating form token and changed layouts), merging and de-duplication,
link sanitising, the search request lifecycle through the worker, the audit
entry, viewer limits, saved searches and the console pages. No test touches the
network: app.fetch.fetch is replaced with a router over the fixtures."""
import datetime as dt
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app import auth, connectors, fetch, tor_search, work_requests, worker
from app.config import settings
from app.db import (AuditLog, Capture, Client, CollectorRun, Hit, Item, SavedSearch, SearchRequest, SessionLocal,
                    Source, User, WatchTerm, utcnow)

FIX = Path(__file__).parent / "fixtures"
AHMIA = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
ONIONLAND = "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion"
TOR66 = "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion"
AKIRA = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"


def _fx(name):
    return (FIX / f"tor_search_{name}.html").read_text()


def _ok(url, html):
    return fetch.FetchResult(url=url, status=200, content=html.encode(), headers={"content-type": "text/html"}, text=html)


class Router:
    """Stands in for app.fetch.fetch. Maps (host, path) to a page and records
    every call with its force_tor flag."""

    def __init__(self, pages=None):
        self.pages = {
            (AHMIA, "/"): _fx("ahmia_home"),
            (AHMIA, "/search/"): _fx("ahmia_results"),
            (ONIONLAND, "/search"): _fx("onionland_results"),
            (TOR66, "/search"): _fx("tor66_results"),
        }
        self.pages.update(pages or {})
        self.calls = []

    def __call__(self, url, force_tor=False, timeout=None, cookies=""):
        self.calls.append((url, force_tor))
        p = urlsplit(url)
        page = self.pages.get((f"{p.scheme}://{p.hostname}", p.path or "/"))
        if page is None:
            return fetch.FetchResult(url=url, status=0, content=b"", headers={}, text="", error="connection refused")
        if isinstance(page, fetch.FetchResult):
            return page
        return _ok(url, page)


@pytest.fixture()
def router(monkeypatch):
    r = Router()
    monkeypatch.setattr(fetch, "fetch", r)
    monkeypatch.setattr(settings, "tor_search_engines", "")
    return r


def _engine(key):
    return next(e for e in tor_search.load_engines("") if e.key == key)


# ---------------------------------------------------------------- adapters
def test_ahmia_scrapes_rotating_token_then_searches(router):
    adapter = tor_search.Adapter(_engine("ahmia"))
    results = adapter.search("acme", 30)
    assert adapter.last_outcome.error == ""
    home, search = router.calls
    assert home == (AHMIA + "/", True)
    qs = parse_qs(urlsplit(search[0]).query)
    assert qs["q"] == ["acme"] and qs["3f9a1c"] == ["b72e04"] and search[1] is True
    urls = [r.url for r in results]
    assert urls[0] == f"http://{AKIRA}/acme-credit-union"
    # The target's own query string survives the unencoded redirect_url parameter.
    assert urls[1].endswith(".onion/post/acme?page=2&sort=new")
    # Percent-encoded targets are decoded; javascript: is dropped.
    assert urls[2].endswith(".onion/p/81") and len(results) == 3
    assert not any(u.startswith("javascript") for u in urls)
    assert all(r.engine == "ahmia" for r in results)
    assert "alert" not in results[1].snippet and "‮" not in results[2].title


def test_ahmia_no_results_is_empty_without_error(router):
    router.pages[(AHMIA, "/search/")] = _fx("ahmia_noresults")
    oc = tor_search.run_engine(_engine("ahmia"), "zzqx")
    assert oc.results == [] and oc.error == "" and oc.status == "empty"


def test_ahmia_homepage_without_form_reports_layout_change(router):
    router.pages[(AHMIA, "/")] = _fx("changed_layout")
    oc = tor_search.run_engine(_engine("ahmia"), "acme")
    assert oc.results == [] and oc.error.startswith("layout changed") and "searchForm" in oc.error
    assert len(router.calls) == 1  # never searched without a token


def test_ahmia_refused_token_redirects_home(router):
    router.pages[(AHMIA, "/search/")] = _ok(AHMIA + "/", _fx("ahmia_home"))
    oc = tor_search.run_engine(_engine("ahmia"), "acme")
    assert oc.results == [] and "token was refused" in oc.error


@pytest.mark.parametrize("key,path", [("ahmia", "/search/"), ("onionland", "/search"), ("tor66", "/search")])
def test_changed_results_layout_returns_empty_with_error(router, key, path):
    base = {"ahmia": AHMIA, "onionland": ONIONLAND, "tor66": TOR66}[key]
    router.pages[(base, path)] = _fx("changed_layout")
    oc = tor_search.run_engine(_engine(key), "acme")
    assert oc.results == [] and oc.error.startswith("layout changed") and oc.status == "error"


def test_onionland_skips_ads_and_self_links_and_decodes_targets(router):
    results = tor_search.Adapter(_engine("onionland")).search("acme", 30)
    assert [r.url for r in results] == [
        f"http://{AKIRA}/acme-credit-union/",
        "http://breachforumxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/Thread-acme-vpn",
    ]
    assert "member database" in results[0].snippet
    assert router.calls[0][0].startswith(ONIONLAND + "/search?q=acme")


def test_tor66_parses_results_after_rule_and_drops_data_urls(router):
    results = tor_search.Adapter(_engine("tor66")).search("acme", 30)
    assert [r.title for r in results] == ["Akira - Acme Credit Union", "acme employee credentials"]
    assert "loan files" in results[0].snippet
    q = parse_qs(urlsplit(router.calls[0][0]).query)
    assert q == {"q": ["acme"], "sorttype": ["rel"], "page": ["1"]}


def test_limit_and_network_failure_never_raise(router, monkeypatch):
    assert len(tor_search.run_engine(_engine("tor66"), "acme", limit=1).results) == 1
    del router.pages[(TOR66, "/search")]
    oc = tor_search.run_engine(_engine("tor66"), "acme")
    assert oc.results == [] and "connection refused" in oc.error

    def boom(engine, html, limit):
        raise ValueError("parser bug")

    monkeypatch.setitem(tor_search.PARSERS, "onionland", boom)
    oc = tor_search.run_engine(_engine("onionland"), "acme")
    assert oc.results == [] and "ValueError: parser bug" in oc.error


# ---------------------------------------------------------------- merge, config, links
def test_run_search_merges_by_host_and_path_and_survives_one_engine(router):
    del router.pages[(ONIONLAND, "/search")]
    out = tor_search.run_search("acme")
    assert all(force for _, force in router.calls)
    assert out["engines"]["onionland"]["status"] == "error"
    assert out["engines"]["ahmia"]["status"] == "ok" and out["engines"]["tor66"]["count"] == 2
    akira = [r for r in out["results"] if r["host"] == AKIRA]
    assert len(akira) == 1 and akira[0]["engines"] == ["ahmia", "tor66"]
    assert all(isinstance(v["ms"], int) for v in out["engines"].values())


def test_merge_dedupes_on_host_and_path_only():
    R = tor_search.Result
    merged = tor_search.merge([
        tor_search.EngineOutcome("ahmia", [R("A", f"http://{AKIRA}/x/", "short", "ahmia")]),
        tor_search.EngineOutcome("tor66", [R("", f"https://{AKIRA.upper()}/x?ref=1#top", "a longer snippet", "tor66"),
                                           R("B", f"http://{AKIRA}/y", "", "tor66")]),
        tor_search.EngineOutcome("onionland", [R("C", "javascript:alert(1)", "", "onionland")]),
    ])
    assert [m["key"] for m in merged] == [f"{AKIRA}/x", f"{AKIRA}/y"]
    assert merged[0]["engines"] == ["ahmia", "tor66"] and merged[0]["title"] == "A"
    assert merged[0]["snippet"] == "a longer snippet" and merged[0]["onion"] is True


@pytest.mark.parametrize("url,ok", [
    (f"http://{AKIRA}/a?b=1", True), ("https://example.com/x", True),
    ("javascript:alert(1)", False), ("data:text/html,hi", False), ("/relative/path", False),
    ("ftp://example.com/", False), ("http://user:pw@example.com/", False), ("http://exa mple.com/", False),
    ("http://example.com/‮path", False), ("vbscript:msgbox", False), ("", False),
])
def test_safe_url(url, ok):
    assert bool(tor_search.safe_url(url)) is ok


def test_engine_config_overrides_and_errors(monkeypatch):
    engines = tor_search.load_engines('[{"key": "tor66", "enabled": false}, '
                                      '{"key": "ahmia", "base_url": "http://newahmiaaddress.onion"}]')
    by = {e.key: e for e in engines}
    assert by["tor66"].enabled is False and by["ahmia"].base_url == "http://newahmiaaddress.onion"
    assert by["ahmia"].token_form == "form#searchForm"
    with pytest.raises(tor_search.EngineConfigError):
        tor_search.load_engines("{not json")
    with pytest.raises(tor_search.EngineConfigError):
        tor_search.load_engines('[{"key": "x", "base_url": "http://x.onion", "search_path": "/", "parser": "nope"}]')
    monkeypatch.setattr(settings, "tor_search_engines", "{not json")
    ok, reason = tor_search.configured()
    assert not ok and "not valid JSON" in reason
    monkeypatch.setattr(settings, "tor_search_engines",
                        '[{"key": "ahmia", "enabled": false}, {"key": "onionland", "enabled": false}, '
                        '{"key": "tor66", "enabled": false}]')
    assert tor_search.configured() == (False, "no search engine enabled in TOR_SEARCH_ENGINES")


def test_scheduler_drains_search_requests_every_15_to_30_seconds():
    job = worker.build_scheduler().get_job("search_requests")
    assert job is not None and job.next_run_time is not None
    assert 15 <= job.trigger.interval.total_seconds() <= 30


# ---------------------------------------------------------------- console and worker (Postgres)
def _as(client, email, role):
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role=role, source="platform"))
            db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def _one(model, **kw):
    db = SessionLocal()
    try:
        return db.query(model).filter_by(**kw).all()
    finally:
        db.close()


def test_live_search_lifecycle_through_the_worker(admin, router):
    page = admin.get("/search/live")
    assert page.status_code == 200 and "Live Tor search" in page.text and 'value="ahmia"' in page.text
    assert not router.calls  # opening the page never touches Tor
    r = admin.post("/search/live", data={"q": "  acme  ", "engine": ["ahmia", "tor66"]}, follow_redirects=False)
    assert r.status_code == 302
    rid = parse_qs(urlsplit(r.headers["location"]).query)["id"][0]
    req = _one(SearchRequest, id=rid)[0]
    assert req.status == "pending" and req.query == "acme" and req.engines == ["ahmia", "tor66"]
    assert req.requested_by == "admin" and not router.calls  # the web container queued it only
    audit = _one(AuditLog, action="search.live")
    assert len(audit) == 1 and audit[0].actor == "admin" and "acme" in audit[0].detail
    assert admin.get(f"/search/live/{rid}/status").json()["status"] == "pending"
    assert "queued for the worker" in admin.get(f"/search/live?id={rid}").text

    assert worker.poll_search_requests() == 1
    req = _one(SearchRequest, id=rid)[0]
    assert req.status == "done" and req.result["total"] >= 3
    assert set(req.result["engines"]) == {"ahmia", "tor66"}
    assert all(not u.startswith(ONIONLAND) for u, _ in router.calls)
    run = _one(CollectorRun, job_id="tor_search")[0]
    assert run.ok is True and run.trigger == "manual" and run.requested_by == "admin"
    assert admin.get(f"/search/live/{rid}/status").json() == {"id": rid, "status": "done", "total": req.result["total"]}

    html = admin.get(f"/search/live?id={rid}").text
    assert "Akira leak: Acme Credit Union" in html and "<script>alert" not in html
    assert f"/research?url=http%3A//{AKIRA}/acme-credit-union" in html
    assert "Add as source" in html and "acme" in admin.get("/search/live").text  # recent searches
    status = {r["key"]: r for r in connectors.status(SessionLocal())}["tor_search"]
    assert status["configured"] and status["state"] == "ok" and status["searches_24h"] == 1
    assert "tor_search" in admin.get("/connectors").text


def test_engine_errors_reach_the_connector_row(admin, router):
    router.pages[(TOR66, "/search")] = _fx("changed_layout")
    admin.post("/search/live", data={"q": "acme", "engine": ["tor66"]})
    worker.poll_search_requests()
    req = _one(SearchRequest)[0]
    assert req.status == "failed" and "layout changed" in req.error
    row = {r["key"]: r for r in connectors.status(SessionLocal())}["tor_search"]
    assert row["state"] == "fail" and "tor66: layout changed" in row["error"]
    assert row["search_engines"]["tor66"]["status"] == "error"


def test_viewer_can_search_but_cannot_add_source_or_save(client, router):
    _as(client, "board@vendettacd.io", "viewer")
    r = client.post("/search/live", data={"q": "acme"}, follow_redirects=False)
    assert r.status_code == 302
    worker.poll_search_requests()
    rid = _one(SearchRequest)[0].id
    page = client.get(f"/search/live?id={rid}").text
    assert "Open in research console" in page and "Add as source" not in page
    r = client.post("/search/live/source", data={"url": f"http://{AKIRA}/", "request_id": rid})
    assert r.status_code == 403
    db = SessionLocal()
    c = Client(name="Acme Credit Union")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    assert client.post(f"/clients/{cid}/saved-searches", data={"q": "acme"}).status_code == 403
    assert not _one(Source, kind="onion") and not _one(SavedSearch)


def test_analyst_adds_onion_result_as_source_once(client, router):
    _as(client, "ana@vendettacd.io", "analyst")
    url = f"http://{AKIRA}/acme-credit-union"
    for _ in range(2):
        r = client.post("/search/live/source", data={"url": url, "title": "Akira‮ leak", "request_id": "r1"},
                        follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/search/live?id=r1&added=1"
    srcs = _one(Source, kind="onion")
    assert len(srcs) == 1 and srcs[0].url == url and srcs[0].name == "Akira leak"
    assert srcs[0].meta["seeded_from"] == "live_search" and srcs[0].profile == ""
    assert client.post("/search/live/source", data={"url": "https://example.com/"}).status_code == 400
    assert client.post("/search/live/source", data={"url": "javascript:alert(1)"}).status_code == 400
    assert len(_one(AuditLog, action="source.add")) == 1


def test_research_prefill_only_accepts_http_urls(admin):
    page = admin.get("/research", params={"url": f"http://{AKIRA}/x"}).text
    assert f'value="http://{AKIRA}/x"' in page
    assert "javascript" not in admin.get("/research", params={"url": "javascript:alert(1)"}).text


def test_nav_renames_search_and_adds_live_search(admin):
    html = admin.get("/search").text
    assert "Search collected data" in html and 'href="/search/live"' in html and "Live Tor search" in html
    assert re.search(r">\s*<svg[^>]*>.*?</svg>\s*Search\s*</a>", html, re.S) is None


def test_saved_search_ingests_matches_and_dedupes(admin, router):
    db = SessionLocal()
    c = Client(name="Acme Credit Union")
    db.add(c)
    db.commit()
    db.add(WatchTerm(client_id=c.id, term="Acme Credit Union", kind="brand", severity="high"))
    db.commit()
    cid = c.id
    db.close()
    r = admin.post(f"/clients/{cid}/saved-searches", data={"q": "acme credit union", "interval_hours": "24",
                                                            "engine": ["ahmia", "onionland", "tor66"]},
                   follow_redirects=False)
    assert r.status_code == 302
    s = _one(SavedSearch, client_id=cid)[0]
    assert s.interval_hours == 24 and s.next_run_at is None
    assert "acme credit union" in admin.get(f"/clients/{cid}").text

    c_tor = connectors.get("tor_search")
    run = worker.run_job(c_tor.job_id, c_tor.job, check=lambda d: c_tor.configured(d))
    assert run.ok is True and run.detail["due"] == 1 and run.detail["searches"] == 1
    items = _one(Item, kind="search")
    assert run.items_new == len(items) >= 4
    akira = [i for i in items if AKIRA in i.url]
    # /acme-credit-union (Ahmia) and /acme-credit-union/ (OnionLand, Tor66) are one result.
    assert len(akira) == 1 and akira[0].meta["engines"] == ["ahmia", "onionland", "tor66"]
    assert akira[0].external_id == f"{AKIRA}/acme-credit-union" and akira[0].meta["client_id"] == cid
    hits = _one(Hit, client_id=cid)
    assert hits and run.hits_new == len(hits)
    assert _one(Capture, client_id=cid)  # capture applies to search items
    s = _one(SavedSearch, id=s.id)[0]
    assert s.last_new_items == len(items) and s.last_error == "" and s.next_run_at > utcnow()
    req = _one(SearchRequest, saved_search_id=s.id)[0]
    assert req.client_id == cid and req.status == "done"
    assert _one(AuditLog, action="search.saved_run")

    # Not due again: nothing queued. Forced due: same results, nothing new ingested.
    run2 = worker.run_job(c_tor.job_id, c_tor.job, check=lambda d: c_tor.configured(d))
    assert run2.detail["due"] == 0 and run2.items_new == 0
    admin.post(f"/clients/{cid}/saved-searches/{s.id}/run")
    run3 = worker.run_job(c_tor.job_id, c_tor.job, check=lambda d: c_tor.configured(d))
    assert run3.detail["due"] == 1 and run3.items_new == 0 and run3.hits_new == 0
    assert len(_one(Item, kind="search")) == len(items)
    assert _one(SavedSearch, id=s.id)[0].last_new_items == 0
    # Live searches are not drained by the saved-search job, nor saved ones by the live poller.
    assert worker.poll_search_requests() == 0


def test_saved_search_toggle_delete_and_paused_client(admin, router):
    db = SessionLocal()
    c = Client(name="Paused Co", active=False)
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    admin.post(f"/clients/{cid}/saved-searches", data={"q": "paused co", "interval_hours": "999"})
    s = _one(SavedSearch, client_id=cid)[0]
    assert s.interval_hours == 24 and s.engines == []
    db = SessionLocal()
    try:
        assert tor_search.queue_due(db) == 0  # paused clients are skipped
    finally:
        db.close()
    admin.post(f"/clients/{cid}/saved-searches/{s.id}/toggle")
    assert _one(SavedSearch, id=s.id)[0].enabled is False
    admin.post(f"/clients/{cid}/saved-searches/{s.id}/delete")
    assert not _one(SavedSearch, client_id=cid)


def test_search_requests_retained_90_days_and_recovered(fresh_db):
    db = SessionLocal()
    try:
        old = utcnow() - dt.timedelta(days=60)
        older = utcnow() - dt.timedelta(days=95)
        db.add_all([SearchRequest(status="done", query="a", requested_at=old),
                    SearchRequest(status="done", query="b", requested_at=older),
                    SearchRequest(status="running", query="c")])
        db.commit()
        assert worker._retention_phase3(db) == 1
        worker._recover_phase3(db)
        rows = {r.query: r for r in db.query(SearchRequest)}
        assert set(rows) == {"a", "c"} and rows["c"].status == work_requests.FAILED
    finally:
        db.close()
