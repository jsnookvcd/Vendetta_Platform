"""Crawl of cybercrime forums and markets over Tor.

A forum source needs a profile (source.profile) of kind forum describing its
board, thread and message selectors. For boards the delivery team has an account
on, store a raw Cookie header on the source (meta.cookie) and it is sent with
every request; nothing logs in on its own. Read only: no posting, replying,
registering or purchasing.

Walks each configured board section, opens thread rows up to a cap, and stores
each message as a "message" item plus the thread as a "thread" item. Watch-term
and IAB matching then run over them through the normal pipeline. Initial access
broker ads live on these boards, so this is where IAB detection earns its keep."""
from __future__ import annotations

import datetime as dt
import logging
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import profiles
from ..db import Source
from ..fetch import absolute, fetch, html_to_text, select_href, select_text, soup_of
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)
PAUSE_SECONDS = 4


def _crawl(db: Session, src: Source, profile: dict) -> None:
    cookies = (src.meta or {}).get("cookie", "")
    sections = profile.get("sections") or ["/"]
    page_param = profile.get("page_param", "")
    max_pages = int(profile.get("max_pages", 1))
    max_threads = int(profile.get("max_threads_per_run", 25))
    threads_done = 0
    seen_threads: list[str] = []

    for section in sections:
        for page in range(1, max_pages + 1):
            if threads_done >= max_threads:
                break
            url = absolute(src.url, section)
            if page_param and page > 1:
                url += ("&" if "?" in url else "?") + f"{page_param}={page}"
            res = fetch(url, cookies=cookies)
            if not res.ok or not res.text:
                mark_source(db, src, False, res.error or f"HTTP {res.status} on {url}")
                continue
            soup = soup_of(res.text)
            try:
                rows = soup.select(profile.get("thread_selector", "")) if profile.get("thread_selector") else []
            except Exception as e:  # noqa: BLE001
                log.warning("bad thread_selector on %s: %s", src.name, e)
                rows = []
            for row in rows:
                if threads_done >= max_threads:
                    break
                title = select_text(row, profile.get("thread_title_selector", "")) or "(thread)"
                href = select_href(row, profile.get("thread_link_selector", ""))
                if not href:
                    continue
                thread_url = absolute(src.url, href)
                if thread_url in seen_threads:
                    continue
                seen_threads.append(thread_url)
                _crawl_thread(db, src, profile, thread_url, title, cookies)
                threads_done += 1
                time.sleep(PAUSE_SECONDS)
            time.sleep(PAUSE_SECONDS)
    mark_source(db, src, True)
    log.info("forum crawl %s: %d threads", src.name, threads_done)


def _crawl_thread(db: Session, src: Source, profile: dict, thread_url: str, title: str, cookies: str) -> None:
    res = fetch(thread_url, cookies=cookies)
    if not res.ok or not res.text:
        return
    soup = soup_of(res.text)
    ingest(
        db, kind="thread", title=f"{src.name}: {title}", body=html_to_text(res.text)[:120_000],
        url=thread_url, external_id=thread_url, group_name=src.group_name or src.name,
        published_at=dt.datetime.now(dt.timezone.utc), source=src,
        hash_parts=("thread", thread_url, title),
    )
    try:
        posts = soup.select(profile.get("post_selector", "")) if profile.get("post_selector") else []
    except Exception:  # noqa: BLE001
        posts = []
    for i, post in enumerate(posts):
        author = select_text(post, profile.get("author_selector", ""))
        date = select_text(post, profile.get("date_selector", ""))
        body = select_text(post, profile.get("body_selector", ""))
        if not body:
            continue
        ingest(
            db, kind="message", title=f"{title} :: {author or 'post ' + str(i)}", body=f"Author: {author}\nDate: {date}\n\n{body}",
            url=thread_url, external_id=f"{thread_url}#p{i}", group_name=src.group_name or src.name,
            published_at=dt.datetime.now(dt.timezone.utc), source=src,
            meta={"author": author, "date_text": date},
            hash_parts=("message", thread_url, str(i), body[:200]),
            preserve_on_hit=False,
        )


def run(db: Session) -> None:
    sources = db.execute(select(Source).where(Source.kind == "forum", Source.enabled.is_(True))).scalars().all()
    for src in sources:
        profile = profiles.get(src.profile) if src.profile else None
        if not profile or profile.get("kind") != "forum":
            mark_source(db, src, False, "forum source needs a profile of kind forum")
            continue
        try:
            _crawl(db, src, profile)
        except Exception as e:  # noqa: BLE001
            log.exception("forum crawl error %s", src.url)
            mark_source(db, src, False, str(e))
