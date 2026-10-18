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
