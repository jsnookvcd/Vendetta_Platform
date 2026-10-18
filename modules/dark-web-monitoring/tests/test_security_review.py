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
