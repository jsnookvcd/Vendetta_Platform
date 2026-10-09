"""Crawl of ransomware leak sites over Tor.

Two modes per source:
  No profile: fetch the index, reduce to visible text, store as a "page" item when
    the text changes. A new victim name shows up as a change and is matched against
    every watch term. This is the zero-config default for the hundreds of seeded
    mirrors.
  With a profile (source.profile names a file in app/profiles/): parse the index
    into individual victim entries, follow each victim's own post over Tor, and
    store a structured "post" item per victim with title, description and date.
    Use this for the groups whose clients you care about most.

Fetched one at a time with a pause between requests. Tor is slow and the goal is a
twice-daily sweep of many mirrors on a tiny instance, not speed. Leak sites go
offline constantly, so a failing source is backed off, never auto-disabled."""
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

PAUSE_SECONDS = 3
MAX_SOURCES_PER_RUN = 150
BACKOFF_AFTER_FAILS = 5
BACKOFF_HOURS = 12


def _due(src: Source, now: dt.datetime) -> bool:
    if (src.fail_count or 0) < BACKOFF_AFTER_FAILS:
        return True
    last_try = (src.meta or {}).get("last_try")
    if not last_try:
        return True
    try:
        return now - dt.datetime.fromisoformat(last_try) > dt.timedelta(hours=BACKOFF_HOURS)
    except ValueError:
        return True


def _crawl_generic(db: Session, src: Source, res, now: dt.datetime) -> None:
    text = html_to_text(res.text) if res.text else ""
    if len(text) < 40:
        mark_source(db, src, False, "empty or non-text response")
        return
    ingest(
        db, kind="page", title=f"{src.group_name or src.name} index", body=text[:200_000],
        url=src.url, external_id=src.url, group_name=src.group_name, published_at=now, source=src,
        meta={"http_status": res.status, "length": len(text)}, hash_parts=("page", src.url, text),
    )
    mark_source(db, src, True)


def _crawl_profiled(db: Session, src: Source, res, profile: dict, now: dt.datetime) -> None:
    cookies = (src.meta or {}).get("cookie", "")
    soup = soup_of(res.text)
    entries = []
    try:
        entries = soup.select(profile.get("list_selector", "")) if profile.get("list_selector") else []
    except Exception as e:  # noqa: BLE001
        log.warning("bad list_selector on %s: %s", src.name, e)
    if not entries:
        # Selectors did not match; fall back so we still catch changes.
        _crawl_generic(db, src, res, now)
        return
    followed = 0
    cap = int(profile.get("max_posts_per_run", 40))
    for entry in entries:
        victim = select_text(entry, profile.get("title_selector", "")) or "(unnamed)"
        desc = select_text(entry, profile.get("desc_selector", ""))
        date = select_text(entry, profile.get("date_selector", ""))
        href = select_href(entry, profile.get("link_selector", ""))
        post_url = absolute(src.url, href) if href else src.url
        body = f"Victim: {victim}\nGroup: {src.group_name}\nDate: {date}\n\n{desc}".strip()
        # Follow the victim's own post for the full description, within the per-run cap.
        if href and followed < cap and (profile.get("post_body_selector") or profile.get("post_title_selector")):
            pr = fetch(post_url, cookies=cookies)
            if pr.ok and pr.text:
                psoup = soup_of(pr.text)
                ptitle = select_text(psoup, profile.get("post_title_selector", ""))
                pbody = select_text(psoup, profile.get("post_body_selector", "")) or html_to_text(pr.text)
                body = f"Victim: {victim}\nGroup: {src.group_name}\nDate: {date}\nTitle: {ptitle}\n\n{pbody[:150_000]}"
            followed += 1
            time.sleep(PAUSE_SECONDS)
        ingest(
            db, kind="post", title=f"{src.group_name}: {victim}", body=body, url=post_url,
            external_id=f"{src.url}#{victim}", group_name=src.group_name, published_at=now, source=src,
            meta={"date_text": date, "profile": profile.get("name")},
            hash_parts=("post", src.group_name, victim.lower(), str(len(body) // 200)),
        )
    mark_source(db, src, True)
    log.info("profiled crawl %s: %d entries, %d posts followed", src.name, len(entries), followed)


def crawl_source(db: Session, src: Source) -> bool:
    now = dt.datetime.now(dt.timezone.utc)
    src.meta = {**(src.meta or {}), "last_try": now.isoformat()}
    res = fetch(src.url, cookies=(src.meta or {}).get("cookie", ""))
    if not res.ok:
        mark_source(db, src, False, res.error or f"HTTP {res.status}")
        return False
    profile = profiles.get(src.profile) if src.profile else None
    if profile and profile.get("kind") == "leak":
        _crawl_profiled(db, src, res, profile, now)
    else:
        _crawl_generic(db, src, res, now)
    return True


def run(db: Session) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    sources = db.execute(
        select(Source).where(Source.kind == "onion", Source.enabled.is_(True)).order_by(Source.last_ok.asc().nullsfirst())
    ).scalars().all()
    done = 0
    for src in sources:
        if done >= MAX_SOURCES_PER_RUN:
            break
        if not _due(src, now):
            continue
        try:
            crawl_source(db, src)
        except Exception as e:  # noqa: BLE001
            log.exception("crawl error %s", src.url)
            mark_source(db, src, False, str(e))
        done += 1
        time.sleep(PAUSE_SECONDS)
    log.info("onion crawl: %d sources attempted", done)
