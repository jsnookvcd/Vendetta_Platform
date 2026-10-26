"""Telegram public channels read from the t.me/s/ web preview.

Every public Telegram channel has a read-only web preview at
https://t.me/s/<channel> that shows its most recent posts without a login, an
API id or a session file. This is the method many open source Telegram OSINT
scrapers use; this collector reads that page instead of the MTProto API, so it
needs nothing configured to run.

Channels come from TELEGRAM_CHANNELS and, when TELEGRAM_WEB_USE_CATALOG is true,
from the online public channels in the deepdarkCTI catalog (app/deepdarkcti.py),
configured channels first. A run reads at most TELEGRAM_WEB_MAX_CHANNELS_PER_RUN
channels and continues through the catalog where the last run stopped, so every
channel is visited over a few runs.

Each post becomes a message item (redacted at ingest like every message), with
the same id and hash the telethon collector uses, so running both never stores a
post twice. A channel's newest post id is kept on its Source and only newer posts
are ingested. The preview shows about the last twenty posts; a channel that posts
faster than the interval can skip some, which the Connectors page cannot see.

Markup read (stable for years): div.tgme_widget_message[data-post="name/123"],
div.tgme_widget_message_text, a.tgme_widget_message_date > time[datetime]. A
page that answers 200 without that markup is recorded as a failure with the
reason, so a layout change shows on the Connectors page instead of passing as an
empty channel."""
from __future__ import annotations

import datetime as dt
import logging
import re
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import deepdarkcti, health
from ..config import settings
from ..db import Source
from ..fetch import FetchResult, fetch, soup_of
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

CHANNEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
STATE_CURSOR = "telegram_web:cursor"


def configured_channels() -> list[str]:
    out = []
    for c in (settings.telegram_channels or "").split(","):
        c = c.strip().lstrip("@")
        if c.startswith(("https://t.me/", "http://t.me/")):
            c = c.split("t.me/", 1)[1].removeprefix("s/").strip("/")
        if CHANNEL_RE.match(c) and c.lower() not in {x.lower() for x in out}:
            out.append(c)
    return out


def catalog_channels(db: Session) -> list[str]:
    """Valid catalog channels not already configured, de-duplicated without case."""
    if not settings.telegram_web_use_catalog:
        return []
    seen = {c.lower() for c in configured_channels()}
    out: list[str] = []
    for c in deepdarkcti.telegram_catalog(db):
        name = str(c.get("channel") or "")
        if CHANNEL_RE.match(name) and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out


def channels_for_run(db: Session) -> tuple[list[str], int, int]:
    """(channels to read now, next catalog cursor, catalog size)."""
    cap = max(1, settings.telegram_web_max_channels_per_run)
    chosen = configured_channels()[:cap]
    catalog = catalog_channels(db)
    room = cap - len(chosen)
    cursor = int((health.get_state(db, STATE_CURSOR) or {}).get("next", 0))
    if not catalog or room <= 0:
        return chosen, cursor, len(catalog)
    cursor %= len(catalog)
    take = [catalog[(cursor + i) % len(catalog)] for i in range(min(room, len(catalog)))]
    return chosen + take, (cursor + len(take)) % len(catalog), len(catalog)


def parse(html: str, channel: str) -> list[dict]:
    """Posts on a preview page: [{"id", "text", "published"}], oldest first.
    Raises ValueError when the page has none of the expected markup."""
    soup = soup_of(html)
    nodes = soup.select("div.tgme_widget_message[data-post]")
    if not nodes:
        if soup.select_one(".tgme_channel_info, .tgme_page_title, .tgme_widget_message_wrap"):
            return []  # a real channel page with no posts shown
        raise ValueError("no Telegram preview markup on the page; the channel may be private or the layout changed")
    out = []
    for n in nodes:
        post = str(n.get("data-post") or "")
        name, _, num = post.rpartition("/")
        if not num.isdigit() or name.lower() != channel.lower():
            continue
        txt_node = n.select_one("div.tgme_widget_message_text")
        text = txt_node.get_text("\n").strip() if txt_node else ""
        when = None
        t = n.select_one("a.tgme_widget_message_date time[datetime]") or n.select_one("time[datetime]")
        if t is not None:
            try:
                when = dt.datetime.fromisoformat(str(t.get("datetime")).replace("Z", "+00:00"))
            except ValueError:
                when = None
        out.append({"id": int(num), "text": text, "published": when})
    out.sort(key=lambda p: p["id"])
    return out


def _source(db: Session, channel: str) -> Source:
    url = f"https://t.me/{channel}"
    src = db.execute(select(Source).where(Source.kind == "telegram", Source.url == url)).scalar_one_or_none()
    if not src:
        src = Source(name=f"Telegram @{channel}", kind="telegram", url=url, group_name=channel)
        db.add(src)
        db.commit()
    return src


def run(db: Session, get: Callable[[str], FetchResult] | None = None) -> dict:
    if not settings.telegram_web_enabled:
        return {"ok": False, "error": "turned off (TELEGRAM_WEB_ENABLED=false)"}
    get = get or (lambda url: fetch(url, force_tor=settings.telegram_web_via_tor))
    channels, next_cursor, catalog_size = channels_for_run(db)
    if not channels:
        return {"ok": True, "channels": 0, "skipped": "no channels: set TELEGRAM_CHANNELS or let the deepdarkCTI "
                                                      "catalog load"}
    new = 0
    failed: list[str] = []
    for channel in channels:
        src = _source(db, channel)
        meta = src.meta or {}
        last_id = int(meta.get("last_message_id", 0) or 0)
        res = get(f"https://t.me/s/{channel}")
        if not res.ok or not res.text:
            err = res.error or f"HTTP {res.status}"
            mark_source(db, src, False, err)
            failed.append(f"@{channel}: {err}")
            continue
        try:
            posts = parse(res.text, channel)
        except ValueError as e:
            mark_source(db, src, False, str(e))
            failed.append(f"@{channel}: {e}")
            continue
        newest = last_id
        for p in posts:
            if p["id"] <= last_id or not p["text"]:
                newest = max(newest, p["id"])
                continue
            newest = max(newest, p["id"])
            item, _ = ingest(
                db,
                kind="message",
                title=f"@{channel} message {p['id']}",
                body=p["text"][:20000],
                url=f"https://t.me/{channel}/{p['id']}",
                external_id=f"tg:{channel}:{p['id']}",
                group_name=channel,
                published_at=p["published"],
                source=src,
                meta={"collector": "telegram_web"},
                hash_parts=("tg", channel, str(p["id"])),
                preserve_on_hit=False,
            )
            new += 1 if item else 0
        src.meta = {**(src.meta or {}), "last_message_id": newest, "collector": "telegram_web"}
        mark_source(db, src, True)
    health.set_state(db, STATE_CURSOR, {"next": next_cursor, "catalog": catalog_size})
    ok = len(failed) < len(channels)
    out = {"ok": ok, "channels": len(channels), "failed": len(failed), "new": new, "catalog": catalog_size}
    if failed:
        out["error"] = "; ".join(failed)[:2000]
    log.info("telegram_web: %s", {k: v for k, v in out.items() if k != "error"})
    return out
