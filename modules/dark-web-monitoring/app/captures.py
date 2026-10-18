"""Aggregator hit, then direct capture.

The aggregator tells us where to look; the direct capture is the record. When an
item produces a hit, pipeline.ingest queues a Capture instead of fetching inline,
so a feed job never blocks on Tor. The worker drains the queue every
CAPTURE_INTERVAL minutes (5), always over Tor:

  target    the original leak post (post_url or claim_url from the feed, or the
            item's own URL) when there is one, otherwise the group's current
            onion index from its enabled Sources, best known first
  mirrors   a post URL is also tried on the group's other onion mirrors (same
            path), then the group's index pages, before the attempt fails
  retries   up to MAX_ATTEMPTS (4) attempts over 24 hours, waiting
            BACKOFF_HOURS (1, 5, 18) between them; then "unavailable"
  record    the page is preserved through evidence.preserve (SHA-256, manifest,
            S3 Object Lock in production) for the hit's client and item, and the
            evidence id is kept on the capture
  no match  an index page captured without the victim's name in its text is
            recorded as "captured_index_no_match"

Statuses: pending, captured, captured_index_no_match, unavailable."""
from __future__ import annotations

import datetime as dt
import logging
import re
import time
from typing import Callable

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import evidence
from .db import Capture, Hit, Item, Source, utcnow
from .fetch import FetchResult, fetch, html_to_text

log = logging.getLogger(__name__)

PENDING, CAPTURED, NO_MATCH, UNAVAILABLE = "pending", "captured", "captured_index_no_match", "unavailable"
MAX_ATTEMPTS = 4
BACKOFF_HOURS = (1, 5, 18)
DRAIN_LIMIT = 20
DRAIN_BUDGET_SECONDS = 240
CAPTURE_KINDS = ("victim", "page", "paste", "search")


def _victim_of(item: Item) -> str:
    meta = item.meta or {}
    raw = meta.get("raw") if isinstance(meta.get("raw"), dict) else {}
    v = meta.get("victim") or raw.get("victim") or raw.get("post_title")
    if v:
        return str(v)[:300]
    title = item.title or ""
    return (title.split(": ", 1)[1] if ": " in title else title)[:300]


def _http(url: str) -> str:
    u = (url or "").strip()
    return u if u.startswith(("http://", "https://")) else ""


def queue_for_hits(db: Session, item: Item, hits: list[Hit], requested_by: str = "system") -> list[Capture]:
    """One capture per hit. Called by pipeline.ingest; never fetches anything."""
    if item.kind not in CAPTURE_KINDS:
        return []
    target = _http(item.url)
    if item.kind != "victim" and not target:
        return []
    out = []
    now = utcnow()
    for hit in hits:
        if db.execute(select(Capture.id).where(Capture.hit_id == hit.id)).first():
            continue
        cap = Capture(hit_id=hit.id, client_id=hit.client_id, item_id=item.id, item_kind=item.kind,
                      group_name=item.group_name or "", victim=_victim_of(item) if item.kind == "victim" else "",
                      target_url=target, status=PENDING, next_attempt_at=now, requested_by=requested_by)
        db.add(cap)
        out.append(cap)
    if out:
        db.commit()
    return out


def for_hit(db: Session, hit_id: str) -> Capture | None:
    return db.execute(select(Capture).where(Capture.hit_id == hit_id)).scalar_one_or_none()


def request_now(db: Session, hit: Hit, actor: str) -> Capture:
    """"Capture now" on the hit page: queue (or re-queue with a fresh set of
    attempts) for the worker's next drain. The web container never fetches."""
    cap = for_hit(db, hit.id)
    item = hit.item
    if cap is None:
        cap = Capture(hit_id=hit.id, client_id=hit.client_id, item_id=item.id, item_kind=item.kind,
                      group_name=item.group_name or "", victim=_victim_of(item) if item.kind == "victim" else "",
                      target_url=_http(item.url))
        db.add(cap)
    cap.status = PENDING
    cap.attempts = 0
    cap.next_attempt_at = utcnow()
    cap.finished_at = None
    cap.requested_by = actor
    cap.updated_at = utcnow()
    db.commit()
    return cap


# ---------------------------------------------------------------- targets
def _group_sources(db: Session, group: str) -> list[Source]:
    if not group:
        return []
    rows = db.execute(
        select(Source).where(Source.kind == "onion", Source.enabled.is_(True),
                             func.lower(Source.group_name) == group.lower())
    ).scalars().all()
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return sorted(rows, key=lambda s: (-(s.last_ok or epoch).timestamp(), s.fail_count or 0, s.url))


def candidates(db: Session, cap: Capture) -> list[tuple[str, str]]:
    """Ordered (url, kind) pairs to try; kind is post, index or direct."""
    out: list[tuple[str, str]] = []

    def add(url: str, kind: str) -> None:
        if url and all(u != url for u, _ in out):
            out.append((url, kind))

    if cap.item_kind and cap.item_kind != "victim":
        add(cap.target_url, "direct")
        return out
    sources = _group_sources(db, cap.group_name)
    if cap.target_url:
        add(cap.target_url, "post")
        try:
            t = httpx.URL(cap.target_url)
        except Exception:  # noqa: BLE001
            t = None
        if t is not None and (t.host or "").endswith(".onion"):
            path = t.raw_path.decode("ascii", "replace") if t.raw_path else "/"
            for s in sources:
                try:
                    su = httpx.URL(s.url)
                except Exception:  # noqa: BLE001
                    continue  # a malformed source URL is skipped, never fatal
                if su.host and su.host != t.host:
                    add(f"{su.scheme}://{su.host}{path}", "post")
    for s in sources:
        add(s.url, "index")
    return out


def victim_variants(victim: str) -> list[str]:
    v = re.sub(r"\s+", " ", (victim or "").strip().lower())
    if not v or v == "(unnamed)":
        return []
    out = [v]
    bare = re.sub(r"^(https?://)?(www\.)?", "", v).split("/")[0]
    if "." in bare and " " not in bare:
        out.append(bare)
        out.append(bare.rsplit(".", 1)[0])
    return [x for x in dict.fromkeys(out) if len(x) >= 3]


def victim_in_text(victim: str, text: str) -> bool:
    t = re.sub(r"\s+", " ", (text or "").lower())
    return any(v in t for v in victim_variants(victim))


# ---------------------------------------------------------------- worker
def _default_fetch(url: str) -> FetchResult:
    from .fetch import is_onion
    from .onion_sources import fetch_onion

    return fetch_onion(url) if is_onion(url) else fetch(url, force_tor=True)


def _fail(db: Session, cap: Capture, error: str, now: dt.datetime, tried: list | None = None) -> str:
    """Count a failed attempt and apply the backoff, or the final unavailable state
    after MAX_ATTEMPTS. Used for ordinary failures and for unexpected exceptions."""
    cap.attempts = (cap.attempts or 0) + 1
    cap.last_error = error[:2000]
    if tried is not None:
        cap.tried = tried[-40:]
    cap.updated_at = now
    if cap.attempts >= MAX_ATTEMPTS:
        cap.status = UNAVAILABLE
        cap.finished_at = now
        cap.next_attempt_at = None
    else:
        cap.next_attempt_at = now + dt.timedelta(hours=BACKOFF_HOURS[min(cap.attempts, len(BACKOFF_HOURS)) - 1])
    db.commit()
    return cap.status


def attempt(db: Session, cap: Capture, fetcher: Callable[[str], FetchResult] | None = None,
            now: dt.datetime | None = None) -> str:
    fetcher = fetcher or _default_fetch
    now = now or utcnow()
    cands = candidates(db, cap)
    errors: list[str] = []
    tried = list(cap.tried or [])
    for url, kind in cands:
        res = fetcher(url)
        ok = bool(res.ok and (res.content or res.text))
        tried.append({"url": url, "kind": kind, "at": now.isoformat(), "status": res.status,
                      "error": (res.error or "")[:200]})
        if not ok:
            errors.append(f"{url}: {res.error or f'HTTP {res.status}'}")
            continue
        status = CAPTURED
        if kind == "index" and cap.victim and not victim_in_text(cap.victim, html_to_text(res.text or "")):
            status = NO_MATCH
        ev = evidence.preserve(db, url, client_id=cap.client_id, item_id=cap.item_id, captured_by="capture-queue",
                               note=f"capture {cap.id} for hit {cap.hit_id} ({kind}{', victim name not found' if status == NO_MATCH else ''})",
                               result=res)
        cap.status, cap.evidence_id, cap.captured_url = status, ev.id, url
        cap.attempts = (cap.attempts or 0) + 1
        cap.last_error = ""
        cap.finished_at = cap.updated_at = now
        cap.next_attempt_at = None
        cap.tried = tried[-40:]
        db.commit()
        return status
    return _fail(db, cap, "; ".join(errors) or "no target: the feed gave no post URL and the group has no enabled onion source",
                 now, tried)


def drain(db: Session, now: dt.datetime | None = None, fetcher: Callable[[str], FetchResult] | None = None,
          clock: Callable[[], float] = time.monotonic, limit: int = DRAIN_LIMIT) -> dict:
    """The worker job. Attempts due captures until the limit or the time budget."""
    now = now or utcnow()
    due = db.execute(
        select(Capture).where(Capture.status == PENDING,
                              (Capture.next_attempt_at.is_(None)) | (Capture.next_attempt_at <= now))
        .order_by(Capture.next_attempt_at.asc().nullsfirst(), Capture.created_at).limit(limit)
    ).scalars().all()
    start = clock()
    counts = {"attempted": 0, CAPTURED: 0, NO_MATCH: 0, UNAVAILABLE: 0, "retrying": 0}
    for cap in due:
        if clock() - start > DRAIN_BUDGET_SECONDS:
            break
        try:
            st = attempt(db, cap, fetcher=fetcher, now=now)
        except Exception as e:  # noqa: BLE001
            log.exception("capture %s failed", cap.id)
            db.rollback()
            st = _fail(db, cap, f"{type(e).__name__}: {e}", now)
        counts["attempted"] += 1
        counts[st if st in (CAPTURED, NO_MATCH, UNAVAILABLE) else "retrying"] += 1
    remaining = db.scalar(select(func.count(Capture.id)).where(Capture.status == PENDING)) or 0
    return {"ok": True, **counts, "queue_depth": remaining}


def stats(db: Session, days: int = 7) -> dict:
    """Queue depth and success rate for the Connectors page (registry extra hook)."""
    since = utcnow() - dt.timedelta(days=days)
    depth = db.scalar(select(func.count(Capture.id)).where(Capture.status == PENDING)) or 0
    rows = db.execute(select(Capture.status, func.count(Capture.id))
                      .where(Capture.status != PENDING, Capture.finished_at >= since)
                      .group_by(Capture.status)).all()
    by = {s: n for s, n in rows}
    done = sum(by.values())
    good = by.get(CAPTURED, 0) + by.get(NO_MATCH, 0)
    return {"capture_queue_depth": depth, "capture_finished_7d": done,
            "capture_success_rate": round(good / done, 3) if done else None,
            "capture_no_match_7d": by.get(NO_MATCH, 0), "capture_unavailable_7d": by.get(UNAVAILABLE, 0)}
