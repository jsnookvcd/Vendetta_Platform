#!/usr/bin/env python3
"""One-time interactive Telegram login that creates the session file the Telegram
collector uses (TELEGRAM_SESSION_PATH, default /data/telegram.session).
Run inside the worker container; see DEPLOY.md:
  docker compose -p vcd-dark-web-monitoring run --rm worker python scripts/telegram_login.py"""
import asyncio
import os

from telethon import TelegramClient  # type: ignore


async def main():
    path = os.environ.get("TELEGRAM_SESSION_PATH") or "/data/telegram.session"
    c = TelegramClient(path, int(os.environ["TELEGRAM_API_ID"]), os.environ["TELEGRAM_API_HASH"])
    await c.start()
    me = await c.get_me()
    print("authorized as", me.username or me.id, "session saved to", path)
    await c.disconnect()


asyncio.run(main())
