"""Security review fixes outside app/fetch.py: link following in the crawlers,
the stored raw HTML cap, profile selector limits and the subprocess timeout,
the capture queue's exception path, the research console's Tor routing and the
live search permissions. No test touches the network: fetches are replaced
with callables returning FetchResult."""
import datetime as dt
from pathlib import Path

import pytest

from app import auth, onion_sources, profile_store
from app.collectors import onion_crawl
from app.config import settings
from app.db import Item, SessionLocal, Source, User
from app.fetch import FetchResult

FIX = Path(__file__).parent / "fixtures"
AKIRA = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
SELECTORS = {"list_selector": "div.card", "title_selector": "h2.company", "link_selector": "a",
             "desc_selector": "p.desc", "date_selector": "span.date"}


def _db():
    return SessionLocal()


def _res(url, html="<html><body>" + "leak site text " * 20 + "</body></html>", status=200, error=""):
    return FetchResult(url=url, status=status, content=html.encode(), headers={"content-type": "text/html"},
                       text=html, error=error)


def _as(client, email, role):
    db = _db()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role=role, source="platform"))
            db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def _onion(db, group="akira", url=f"http://{AKIRA}/", profile=""):
    src = Source(name=f"{group} mirror", kind="onion", url=url, group_name=group, profile=profile)
    db.add(src)
    db.commit()
    return src


# ---------------------------------------------------------------- stored raw HTML cap
def test_stored_index_html_is_capped_at_fetch_max_bytes(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "fetch_max_bytes", 500)
    html = "<html><body>" + "<p>café victim listing</p>" * 400 + "</body></html>"
    monkeypatch.setattr(onion_sources, "fetch_onion", lambda url, cookies="": _res(url, html=html))
    db = _db()
    try:
        onion_crawl.crawl_source(db, _onion(db))
        page = db.query(Item).filter_by(kind="page").one()
        assert 0 < len(page.meta["html"].encode("utf-8")) <= 500
    finally:
        db.close()


# ---------------------------------------------------------------- crawler link following
HOSTILE_INDEX = f"""<html><body>
<div class="card"><h2 class="company">Acme Federal Credit Union</h2><a href="/acme">More</a></div>
<div class="card"><h2 class="company">Metadata Corp</h2><a href="http://169.254.169.254/latest/meta-data/">More</a></div>
<div class="card"><h2 class="company">Platform Inc</h2><a href="http://platform:8000/api/clients">More</a></div>
<div class="card"><h2 class="company">Elsewhere LLC</h2><a href="http://otheronionhostexampleeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion/x">More</a></div>
<div class="card"><h2 class="company">Clearnet Ltd</h2><a href="https://example.com/post">More</a></div>
</body></html>"""


def test_profiled_crawl_only_follows_posts_on_the_sources_own_host(fresh_db, monkeypatch):
    monkeypatch.setattr(onion_crawl, "PAUSE_SECONDS", 0)
    monkeypatch.setattr(onion_sources, "fetch_onion", lambda url, cookies="": _res(url, html=HOSTILE_INDEX))
    followed = []

    def fake_fetch(url, force_tor=False, timeout=None, cookies=""):
        followed.append((url, force_tor))
        return _res(url, html="<html><body><h1>post</h1><div class='b'>full post body</div></body></html>")

    monkeypatch.setattr(onion_crawl, "fetch", fake_fetch)
    db = _db()
    try:
        profile_store.save(db, "akira", "akira", {**SELECTORS, "post_body_selector": "div.b",
                                                  "max_posts_per_run": 40}, "admin", apply_to_sources=False)
        src = _onion(db, profile="group-akira")
        assert onion_crawl.crawl_source(db, src) is True
        assert followed == [(f"http://{AKIRA}/acme", True)]
        assert db.query(Item).filter_by(kind="post").count() == 5  # every entry still stored
    finally:
        db.close()


def test_forum_crawl_only_follows_threads_on_the_sources_own_host_over_tor(fresh_db, monkeypatch):
    from app.collectors import forum_crawl

    board = f"""<html><body>
    <tr class="t"><a class="l" href="/thread/1">Selling VPN access</a></tr>
    <tr class="t"><a class="l" href="http://db:5432/">Internal</a></tr>
    <tr class="t"><a class="l" href="http://169.254.169.254/latest/">Metadata</a></tr>
    <tr class="t"><a class="l" href="https://example.com/thread/2">Clearnet</a></tr>
    </body></html>"""
    profile = {"kind": "forum", "sections": ["/board"], "thread_selector": "tr.t", "thread_title_selector": "a.l",
               "thread_link_selector": "a.l", "post_selector": "div.p", "body_selector": "div.p"}
    monkeypatch.setattr(forum_crawl.profiles, "get", lambda name: profile)
    monkeypatch.setattr(forum_crawl, "PAUSE_SECONDS", 0)
    monkeypatch.setattr(forum_crawl.time, "sleep", lambda s: None)
    calls = []

    def fake_fetch(url, force_tor=False, timeout=None, cookies=""):
        calls.append((url, force_tor))
        if url.endswith("/board"):
            return _res(url, html=board)
        return _res(url, html="<html><body><div class='p'>post text here</div></body></html>")

    monkeypatch.setattr(forum_crawl, "fetch", fake_fetch)
    db = _db()
    try:
        src = Source(name="exampleforum", kind="forum", url=f"http://{AKIRA}/", profile="f")
        db.add(src)
        db.commit()
        out = forum_crawl.run(db)
        assert out["ok"] is True
        assert calls == [(f"http://{AKIRA}/board", True), (f"http://{AKIRA}/thread/1", True)]
    finally:
        db.close()


# ---------------------------------------------------------------- capture queue exception path
def _victim_capture(db, url):
    from app.db import Client, WatchTerm
    from app.pipeline import ingest

    c = Client(name="Acme Federal Credit Union")
    db.add(c)
    db.commit()
    db.add(WatchTerm(client_id=c.id, term="Acme Federal Credit Union", kind="brand", severity="high"))
    feed = Source(name="ransomware.live recent victims", kind="feed", url="https://api-pro.ransomware.live/victims/recent")
    db.add(feed)
    db.commit()
    _, hits = ingest(db, kind="victim", title="akira: Acme Federal Credit Union", body="Victim: Acme Federal Credit Union",
                     url=url, group_name="akira", source=feed, meta={"victim": "Acme Federal Credit Union"},
                     hash_parts=("victim", "akira", url))
    assert hits


def test_capture_exception_counts_the_attempt_and_ends_unavailable(fresh_db):
    from app import captures
    from app.db import Capture, utcnow

    def boom(url):
        raise RuntimeError("parser exploded")

    db = _db()
    try:
        _victim_capture(db, f"http://{AKIRA}/acme")
        now = utcnow()
        captures.drain(db, now=now, fetcher=boom)
        cap = db.query(Capture).one()
        assert cap.status == "pending" and cap.attempts == 1 and "parser exploded" in cap.last_error
        assert cap.next_attempt_at == now + dt.timedelta(hours=1)
        assert captures.drain(db, now=now + dt.timedelta(minutes=5), fetcher=boom)["attempted"] == 0
        t = now
        for hours in captures.BACKOFF_HOURS:
            t += dt.timedelta(hours=hours)
            captures.drain(db, now=t, fetcher=boom)
        db.refresh(cap)
        assert cap.status == "unavailable" and cap.attempts == captures.MAX_ATTEMPTS and cap.next_attempt_at is None
    finally:
        db.close()


def test_malformed_source_url_fails_the_capture_cleanly(fresh_db):
    from app import captures
    from app.db import Capture

    db = _db()
    try:
        _onion(db, url="http://a:b:c/")
        _victim_capture(db, f"http://{AKIRA}/acme")
        cap = db.query(Capture).one()
        cands = captures.candidates(db, cap)
        assert (f"http://{AKIRA}/acme", "post") in cands
        st = captures.attempt(db, cap, fetcher=lambda u: _res(u, status=0, error="refused: invalid URL"))
        assert st == "pending" and cap.attempts == 1 and cap.last_error
        assert captures._default_fetch("http://a:b:c/").error  # no exception escapes the default fetcher
    finally:
        db.close()


# ---------------------------------------------------------------- profile selector cost
def slow_extract(*args, **kwargs):
    """Runs in the spawned subprocess in place of the real extraction."""
    import time

    time.sleep(30)
    return []


def _stored_page(db, group="akira"):
    html = (FIX / "leak_index.html").read_text()
    src = _onion(db, group)
    db.add(Item(source_id=src.id, kind="page", title=f"{group} index", body="text", url=src.url, group_name=group,
                content_hash=Item.make_hash("page", group), meta={"html": html}))
    db.commit()
    return src


def test_profile_route_is_a_plain_def():
    import inspect

    from app import main

    assert not inspect.iscoroutinefunction(main.profile_preview_or_save)


def test_profile_editor_refuses_long_or_many_part_selectors(admin):
    from app.db import ParserProfile

    db = _db()
    try:
        _stored_page(db)
    finally:
        db.close()
    long_sel = "div" + " div" * 60
    r = admin.post("/priority-groups/akira/profile", data={**SELECTORS, "list_selector": long_sel, "action": "save"},
                   follow_redirects=False)
    assert r.status_code == 400 and "limit is 200" in r.text
    many = ", ".join(f"div.c{i}" for i in range(11))
    r = admin.post("/priority-groups/akira/profile", data={**SELECTORS, "title_selector": many, "action": "preview"})
    assert r.status_code == 400 and "limit is 10" in r.text
    assert _db().query(ParserProfile).count() == 0
    r = admin.post("/priority-groups/akira/profile", data={**SELECTORS, "action": "preview"})
    assert r.status_code == 200 and "Acme Federal Credit Union" in r.text


def test_profile_preview_times_out_with_a_clear_error(admin, monkeypatch):
    from app import selectors_safe

    db = _db()
    try:
        _stored_page(db)
    finally:
        db.close()
    monkeypatch.setattr(selectors_safe, "TIMEOUT_SECONDS", 2)
    monkeypatch.setattr(selectors_safe, "extract_entries", slow_extract)
    started = dt.datetime.now()
    r = admin.post("/priority-groups/akira/profile", data={**SELECTORS, "action": "preview"})
    assert (dt.datetime.now() - started).total_seconds() < 15
    assert r.status_code == 200 and "Preview stopped after 2 seconds" in r.text


def test_crawl_selector_timeout_yields_no_entries_for_the_run(fresh_db, monkeypatch):
    from app import selectors_safe

    html = (FIX / "leak_index.html").read_text()
    monkeypatch.setattr(onion_sources, "fetch_onion", lambda url, cookies="": _res(url, html=html))
    monkeypatch.setattr(selectors_safe, "TIMEOUT_SECONDS", 2)
    monkeypatch.setattr(selectors_safe, "extract_entries", slow_extract)
    db = _db()
    try:
        profile_store.save(db, "akira", "akira", {**SELECTORS, "max_posts_per_run": 0}, "admin", apply_to_sources=False)
        src = _onion(db, profile="group-akira")
        assert onion_crawl.crawl_source(db, src) is True
        assert db.query(Item).filter_by(kind="post").count() == 0
        assert db.query(Item).filter_by(kind="page").count() == 1  # generic fallback still stores the index
        assert db.get(Source, src.id).meta["profile_last_entries"] == 0
    finally:
        db.close()


def test_crawl_refuses_profiles_over_the_selector_limits(fresh_db, monkeypatch):
    from app.collectors import forum_crawl

    html = (FIX / "leak_index.html").read_text()
    monkeypatch.setattr(onion_sources, "fetch_onion", lambda url, cookies="": _res(url, html=html))
    db = _db()
    try:
        profile_store.save(db, "akira", "akira", {**SELECTORS, "list_selector": "div.card," * 12,
                                                  "max_posts_per_run": 0}, "admin", apply_to_sources=False)
        src = _onion(db, profile="group-akira")
        onion_crawl.crawl_source(db, src)
        assert db.query(Item).filter_by(kind="post").count() == 0
        monkeypatch.setattr(forum_crawl.profiles, "get", lambda n: {"kind": "forum", "thread_selector": "a" * 300})
        monkeypatch.setattr(forum_crawl, "fetch", lambda *a, **k: pytest.fail("refused profile must not fetch"))
        db.add(Source(name="f", kind="forum", url=f"http://{AKIRA}/", profile="f"))
        db.commit()
        out = forum_crawl.run(db)
        assert out["ok"] is False and "limit is 200" in out["error"]
    finally:
        db.close()
