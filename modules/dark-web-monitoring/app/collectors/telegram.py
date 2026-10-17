"""Telegram public channel monitoring (optional). Ransomware affiliates, initial
access brokers and combolist sellers advertise on public channels. telethon is in
requirements.txt. Set TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_CHANNELS
(comma separated usernames). The first run needs an interactive login to create
the session file at TELEGRAM_SESSION_PATH; do that once with
scripts/telegram_login.py (see DEPLOY.md). Until the settings and the session file
exist the Connectors page shows which one is missing and the job does not run."""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Source
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)
SESSION_PATH = "/data/telegram.session"  # default; settings.telegram_session_path wins


def session_path() -> str:
    return settings.telegram_session_path or SESSION_PATH


def _source(db: Session, channel: str) -> Source:
    url = f"https://t.me/{channel}"
    src = db.execute(select(Source).where(Source.kind == "telegram", Source.url == url)).scalar_one_or_none()
    if not src:
        src = Source(name=f"Telegram @{channel}", kind="telegram", url=url, group_name=channel)
        db.add(src)
        db.commit()
    return src


async def _collect(db: Session) -> dict:
    from telethon import TelegramClient  # type: ignore

    client = TelegramClient(session_path(), int(settings.telegram_api_id), settings.telegram_api_hash)
    await client.connect()
    if not await client.is_user_authorized():
        log.error("telegram session not authorized; run scripts/telegram_login.py")
        await client.disconnect()
        return {"ok": False, "error": "telegram session not authorized; run scripts/telegram_login.py"}
    failed: list[str] = []
    channels = [c.strip().lstrip("@") for c in settings.telegram_channels.split(",") if c.strip()]
    for channel in channels:
        src = _source(db, channel)
        last_id = int((src.meta or {}).get("last_message_id", 0))
        try:
            newest = last_id
            async for msg in client.iter_messages(channel, min_id=last_id, limit=200):
                if not msg.text:
                    continue
                newest = max(newest, msg.id)
                ingest(
                    db,
                    kind="message",
                    title=f"@{channel} message {msg.id}",
                    body=msg.text,
                    url=f"https://t.me/{channel}/{msg.id}",
                    external_id=f"tg:{channel}:{msg.id}",
                    group_name=channel,
                    published_at=msg.date,
                    source=src,
                    hash_parts=("tg", channel, str(msg.id)),
                    preserve_on_hit=False,
                )
            src.meta = {**(src.meta or {}), "last_message_id": newest}
            mark_source(db, src, True)
        except Exception as e:  # noqa: BLE001
            mark_source(db, src, False, str(e))
            failed.append(f"@{channel}: {e}")
    await client.disconnect()
    if channels and len(failed) == len(channels):
        return {"ok": False, "error": "; ".join(failed)[:2000], "channels": len(channels)}
    return {"ok": True, "channels": len(channels), "failed": len(failed)}


def run(db: Session) -> dict:
    if not (settings.telegram_api_id and settings.telegram_api_hash and settings.telegram_channels):
        return {"ok": True, "skipped": "TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_CHANNELS not all set"}
    try:
        import telethon  # noqa: F401
    except ImportError:
        log.info("telethon not installed; telegram collector skipped")
        return {"ok": True, "skipped": "telethon not installed"}
    import os

    if not os.path.exists(session_path()):
        return {"ok": False, "error": f"no Telegram session file at {session_path()}; run scripts/telegram_login.py"}
    return asyncio.run(_collect(db))
