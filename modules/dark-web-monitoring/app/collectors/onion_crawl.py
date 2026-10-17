"""Crawl of ransomware leak sites over Tor.

Two modes per source:
  No profile: fetch the index, reduce to visible text, store as a "page" item when
    the text changes. A new victim name shows up as a change and is matched against
    every watch term. The raw HTML is kept in the item's meta (capped) so the
    profile editor on the Priority Groups page can preview selectors against it.
  With a profile (source.profile names a database profile or a YAML file in
    app/profiles/, see app/profile_store.py): parse the index into individual
    victim entries, follow each victim's own post over Tor, and store a
    structured "post" item per victim with title, description and date. A
    profile that extracted entries before and now extracts none is marked broken.

Order and limits (app/onion_sources.py): priority groups first and every run,
then the rest by group activity, newest first. A run stops at
ONION_CRAWL_BUDGET_MINUTES of wall-clock time (45) and, for non-priority
sources, at MAX_SOURCES_PER_RUN. A failing source backs off to a 12 hour retry
after 5 failures; the daily disable rules turn it off after 10 in a row."""
from __future__ import annotations

import datetime as dt
import logging
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import onion_sources, profile_store
from ..config import settings
from ..db import Source
from ..fetch import absolute, fetch, html_to_text, select_text, soup_of
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

PAUSE_SECONDS = 3
MAX_SOURCES_PER_RUN = 150
BACKOFF_AFTER_FAILS = 5
BACKOFF_HOURS = 12
PAGE_HTML_CAP = 400_000


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
        meta={"http_status": res.status, "length": len(text), "html": (res.text or "")[:PAGE_HTML_CAP],
              "final_url": res.url},
        hash_parts=("page", src.url, text),
    )
    mark_source(db, src, True)


def _crawl_profiled(db: Session, src: Source, res, profile: dict, now: dt.datetime) -> None:
    cookies = (src.meta or {}).get("cookie", "")
    entries = []
    try:
        entries = soup_of(res.text).select(profile.get("list_selector", "")) if profile.get("list_selector") else []
    except Exception as e:  # noqa: BLE001
        log.warning("bad list_selector on %s: %s", src.name, e)
    state = profile_store.record_crawl(db, src, profile.get("name") or src.profile, len(entries), now)
    if not entries:
        if state == "broken":
            log.warning("profile %s on %s extracted no entries; marked broken", src.profile, src.name)
        # Selectors did not match; fall back so we still catch changes.
        _crawl_generic(db, src, res, now)
        return
    followed = 0
    cap = int(profile.get("max_posts_per_run", 40))
    for entry in profile_store.extract(res.text, profile):
        victim, desc, date, href = entry["victim"], entry["desc"], entry["date"], entry["link"]
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
            meta={"date_text": date, "profile": profile.get("name"), "victim": victim},
            hash_parts=("post", src.group_name, victim.lower(), str(len(body) // 200)),
        )
    mark_source(db, src, True)
    log.info("profiled crawl %s: %d entries, %d posts followed", src.name, len(entries), followed)


def crawl_source(db: Session, src: Source) -> bool:
    now = dt.datetime.now(dt.timezone.utc)
    src.meta = {**(src.meta or {}), "last_try": now.isoformat()}
    res = onion_sources.fetch_onion(src.url, cookies=(src.meta or {}).get("cookie", ""))
    if not res.ok:
        mark_source(db, src, False, res.error or f"HTTP {res.status}")
        return False
    profile = profile_store.get(db, src.profile) if src.profile else None
    if profile and profile.get("kind") == "leak":
        _crawl_profiled(db, src, res, profile, now)
    else:
        _crawl_generic(db, src, res, now)
    return True


def run(db: Session, clock=time.monotonic, sleep=time.sleep) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    sources = db.execute(select(Source).where(Source.kind == "onion", Source.enabled.is_(True))).scalars().all()
    budget = max(1, settings.onion_crawl_budget_minutes) * 60
    start = clock()
    done = failed = priority_done = 0
    last_error = ""
    budget_hit = False
    for src, is_priority in onion_sources.crawl_order(db, sources):
        if clock() - start >= budget:
            budget_hit = True
            break
        if not is_priority and done - priority_done >= MAX_SOURCES_PER_RUN:
            break
        if not _due(src, now):
            continue
        try:
            if not crawl_source(db, src):
                failed += 1
                last_error = src.last_error
        except Exception as e:  # noqa: BLE001
            log.exception("crawl error %s", src.url)
            db.rollback()
            mark_source(db, src, False, str(e))
            failed += 1
            last_error = str(e)
        done += 1
        priority_done += 1 if is_priority else 0
        sleep(PAUSE_SECONDS)
    log.info("onion crawl: %d sources attempted (%d priority)%s", done, priority_done,
             "; stopped at the time budget" if budget_hit else "")
    summary = {"ok": True, "attempted": done, "priority_attempted": priority_done, "failed": failed,
               "enabled_sources": len(sources), "budget_exhausted": budget_hit,
               "elapsed_seconds": int(clock() - start)}
    if done and failed == done:
        # Every mirror failing at once usually means Tor itself is down.
        summary.update(ok=False, error=f"all {done} attempted onion sources failed; last error: {last_error}"[:2000])
    return summary
