"""Ingest -> dedupe -> match -> alert -> preserve. Every collector calls ingest()."""
from __future__ import annotations

import contextvars
import dataclasses
import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import alerts, evidence, iab
from .db import Hit, Item, Source
from .matcher import match_item
from .redact import redact_for_kind

log = logging.getLogger(__name__)


@dataclasses.dataclass
class RunStats:
    """New items and hits produced during one collector run. The worker's job
    wrapper opens one per run so every collector is counted without each having
    to tally its own ingest calls."""

    items: int = 0
    hits: int = 0


_run_stats: contextvars.ContextVar[RunStats | None] = contextvars.ContextVar("run_stats", default=None)


def begin_stats() -> tuple[RunStats, contextvars.Token]:
    stats = RunStats()
    return stats, _run_stats.set(stats)


def end_stats(token: contextvars.Token) -> None:
    _run_stats.reset(token)


def ingest(
    db: Session,
    kind: str,
    title: str,
    body: str,
    url: str = "",
    external_id: str = "",
    group_name: str = "",
    published_at: dt.datetime | None = None,
    source: Source | None = None,
    meta: dict | None = None,
    hash_parts: tuple[str, ...] | None = None,
    preserve_on_hit: bool = True,
) -> tuple[Item | None, list[Hit]]:
    """Returns (item, new_hits). item is None when the record was already seen."""
    h = Item.make_hash(*(hash_parts or (kind, external_id or url, title, body[:2000])))
    if db.execute(select(Item.id).where(Item.content_hash == h)).first():
        return None, []
    # Mask secrets before anything is written for kinds that carry them.
    body = redact_for_kind(kind, body)
    item = Item(
        source_id=source.id if source else None,
        kind=kind,
        external_id=external_id[:300],
        group_name=group_name[:100],
        title=title[:5000],
        body=body,
        url=url,
        published_at=published_at,
        content_hash=h,
        meta=meta or {},
    )
    db.add(item)
    db.commit()
    hits = match_item(db, item)
    hits += iab.match_iab(db, item)
    stats = _run_stats.get()
    if stats is not None:
        stats.items += 1
        stats.hits += len(hits)
    if hits:
        log.info("%d hit(s) on %s item %s", len(hits), kind, item.title[:80])
        alerts.dispatch(db, hits)
        if preserve_on_hit and url and kind in ("victim", "page", "paste"):
            for hit in hits:
                try:
                    evidence.preserve(db, url, client_id=hit.client_id, item_id=item.id, note=f"auto: hit {hit.id}")
                except Exception as e:  # noqa: BLE001
                    log.error("evidence preserve failed for %s: %s", url, e)
    return item, hits


def mark_source(db: Session, source: Source, ok: bool, error: str = "") -> None:
    if ok:
        source.last_ok = dt.datetime.now(dt.timezone.utc)
        source.last_error = ""
        source.fail_count = 0
    else:
        source.last_error = error[:2000]
        source.fail_count = (source.fail_count or 0) + 1
    db.add(source)
    db.commit()
